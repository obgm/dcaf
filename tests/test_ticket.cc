/*
 * test_ticket.cc -- DCAF authorization ticket handling
 *
 * Copyright (C) 2018-2021 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <iostream>
#include <memory>
#include <functional>

#include "dcaf/ace.h"
#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_am.h"
#include "dcaf/dcaf_prng.h"
#include "dcaf/cose.h"

#include "test.hh"
#include "catch.hpp"

/**
 * Checks if the numeric @p option exists in @p pdu and is equal to
 * @p value and returns true if this is the case, false otherwise.
 */
static bool
test_option_eq(const coap_pdu_t *pdu, unsigned int option, long value) {
  coap_opt_iterator_t oi;
  coap_opt_t *opt = coap_check_option((coap_pdu_t *)pdu, option, &oi);
  coap_option_t parsed;

  if (opt && (coap_opt_parse(opt, coap_opt_size(opt), &parsed) > 0)) {
    return value == coap_decode_var_bytes(parsed.value, parsed.length);
  } else {
    return false;
  }
}

SCENARIO( "DCAF ticket request", "[ticket]" ) {
  static std::unique_ptr<dcaf_ticket_t, Deleter> ticket;
  static std::unique_ptr<dcaf_ticket_request_t, Deleter> treq;
  static std::unique_ptr<coap_pdu_t, Deleter> coap_pdu{
    coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET,
                  0, COAP_DEFAULT_MTU)};
  static std::unique_ptr<coap_pdu_t, Deleter> coap_response{
    coap_pdu_init(COAP_MESSAGE_ACK, COAP_RESPONSE_CODE_CONTENT,
                  0, COAP_DEFAULT_MTU)};
  static std::unique_ptr<cose_obj_t, Deleter> object;
  static std::unique_ptr<abor_decoder_t, Deleter> ticket_face;
  static std::unique_ptr<abor_decoder_t, Deleter> claim;
  static std::unique_ptr<dcaf_aif_t, Deleter> aif;
  static std::unique_ptr<dcaf_key_t, Deleter> s_key;

  static const dcaf_key_t rs_key = {
    (dcaf_key_type)COSE_AES_CCM_16_64_128,
    {}, 0,
    0, /* flags */
    { 0x52, 0x53, 0x27, 0x73, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x32, 0x33, 0x34, 0x35, 0x36 },
    16
  };

  static uint8_t buf[1024];
  static size_t buflen = sizeof(buf);
  
  GIVEN("A shared secret and a ticket request") {
    const uint8_t kid_data[] = { 'b', 'a', 'r' };
  
    s_key.reset(dcaf_new_key(DCAF_AES_128));
    REQUIRE(s_key != nullptr);
    REQUIRE(dcaf_set_key(s_key.get(), rs_key.data, rs_key.length));
    REQUIRE(dcaf_set_kid(s_key.get(), kid_data, sizeof(kid_data)));
    dcaf_add_key(dcaf_context(), NULL, s_key.get());

    static uint8_t coap_data[] = {
      (COAP_DEFAULT_VERSION << 6) | (COAP_MESSAGE_NON << 4), /* TKL == 0 */
      COAP_REQUEST_POST, 0x12, 0x34, /* arbitray mid */
      (COAP_OPTION_CONTENT_FORMAT << 4) | 1, DCAF_MEDIATYPE_DCAF_CBOR,
      COAP_PAYLOAD_START,
      0xA4, 0x01, 0x63, 0x66, 0X6F, 0X6F, 0x03, 0x63,
      0x62, 0x61, 0x72, 0x09, 0x82, 0x62, 0X2F, 0x72,
      0x05, 0x18, 0X7D, 0x48, 0x41, 0x42, 0x43, 0x44,
      0x45, 0x46, 0x47, 0x48
    };

    WHEN("The request is parsed") {
      dcaf_ticket_request_t *result;

      REQUIRE(coap_pdu.get() != nullptr);
      // FIXME: As of version 4.3, coap_pdu_parse() is in libcoap's internal API 
      // REQUIRE(coap_pdu_parse(COAP_PROTO_UDP,
      //                        coap_data, sizeof(coap_data),
      //                        coap_pdu.get()) > 0);

      THEN("dcaf_parse_ticket_request() returns DCAF_OK") {
        dcaf_result_t res;
        res = dcaf_parse_ticket_request(nullptr, coap_pdu.get(), &result);
        REQUIRE(res == DCAF_OK);
        REQUIRE(result != nullptr);
        treq.reset(result);
      }
    }

    WHEN("A validated dcaf_ticket_request_t structure is available") {
      coap_session_t *session;
      session = coap_new_client_session(dcaf_get_coap_context(dcaf_context()),
                                        nullptr, nullptr, COAP_PROTO_UDP);
      REQUIRE(session != nullptr);
      REQUIRE(treq.get() != nullptr);

      THEN("a ticket grant can be created") {
        dcaf_set_ticket_grant(session, treq.get(), coap_response.get());
        REQUIRE(coap_pdu_get_code(coap_response.get()) == COAP_RESPONSE_CODE_CREATED);

        /* check Content-Format */
        REQUIRE(test_option_eq(coap_response.get(),
                               COAP_OPTION_CONTENT_FORMAT,
                               DCAF_MEDIATYPE_DCAF_CBOR));

        /* check CBOR payload */
        size_t databuf_len;
        const uint8_t *databuf;
        cn_cbor *data;
        REQUIRE(coap_get_data(coap_response.get(), &databuf_len, &databuf));
        data = cn_cbor_decode(databuf, databuf_len, nullptr);
        REQUIRE(data != nullptr);
      }
    }

    WHEN("A ticket grant was created") {
      size_t databuf_len;
      const uint8_t *databuf;
      REQUIRE(coap_get_data(coap_response.get(), &databuf_len, &databuf));

      REQUIRE(databuf != nullptr);

      THEN("The grant must contain a ticket face") {
        /* The ticket face is part of claim and thus must not be deleted. */
        claim.reset(abor_decode_start(databuf, databuf_len));

        REQUIRE(claim != nullptr);
        ticket_face.reset(abor_mapget_int(claim.get(), DCAF_CINFO_TICKET_FACE));
        REQUIRE(ticket_face != nullptr);
      }
    }

    WHEN("A ticket grant with client information is present") {
      REQUIRE(claim != nullptr);

      THEN("The client information must contain a cnf claim with a symmetric key") {
        std::unique_ptr<abor_decoder_t, Deleter> cnf;
        std::unique_ptr<abor_decoder_t, Deleter> cwt_key, kty, k;
        cnf.reset(abor_mapget_int(claim.get(), DCAF_TICKET_CNF));
        REQUIRE(cnf != nullptr);
        REQUIRE(abor_check_type(cnf.get(), ABOR_MAP));

        cwt_key.reset(abor_mapget_int(cnf.get(), CWT_COSE_KEY));
        REQUIRE(cwt_key != nullptr);
        REQUIRE(abor_check_type(cwt_key.get(), ABOR_MAP));

        kty.reset(abor_mapget_int(cwt_key.get(), COSE_KEY_KTY));
        REQUIRE(kty != nullptr);
        REQUIRE(abor_check_type(kty.get(), ABOR_UINT));

        uint64_t num;
        REQUIRE(abor_get_uint(kty.get(), &num));
        REQUIRE(num == COSE_KEY_KTY_SYMMETRIC);

        k.reset(abor_mapget_int(cwt_key.get(), COSE_KEY_K));
        REQUIRE(k != nullptr);
        REQUIRE(abor_check_type(k.get(), ABOR_BSTR));

        /* use the same not-so-random key sequence */
        uint8_t key[16];
        dcaf_prng(key, sizeof(key));

        REQUIRE(abor_get_sequence_length(k.get()) == sizeof(key));
        REQUIRE(memcmp(abor_get_bytes(k.get()), key, sizeof(key)) == 0);
      }
    }

    WHEN("A ticket grant with an encrypted ticket face is present") {
      const uint8_t t_face[] = { 
        0x58, 0x5c, 0x83, 0x43, 0xa1, 0x01, 0x0a, 0xa1,
        0x05, 0x4d, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x58,
        0x45, 0xdc, 0x17, 0xc0, 0xea, 0x0c, 0x69, 0x04,
        0x94, 0x53, 0x3c, 0x58, 0x6f, 0x1f, 0x92, 0x89,
        0x5e, 0xbb, 0x4b, 0xfb, 0xab, 0x62, 0xec, 0x95,
        0x04, 0x15, 0x11, 0x75, 0xcb, 0x7f, 0xec, 0xef,
        0xc1, 0x8f, 0xd2, 0xa3, 0xe8, 0x22, 0x5a, 0x07,
        0x4b, 0xf9, 0x66, 0x99, 0xb4, 0xe6, 0xcc, 0xaf,
        0x25, 0x10, 0xef, 0x71, 0xf7, 0xc2, 0xa5, 0x39,
        0xc8, 0xdb, 0x02, 0x41, 0x2f, 0x34, 0xef, 0x6f,
        0x51, 0x22, 0x19, 0xce, 0xc6, 0xa3
      };
      const uint8_t decrypted_t_face[] = { 
        0xa7, 0x03, 0x63, 0x62, 0x61, 0x72, 0x09, 0x82,
        0x62, 0x2f, 0x72, 0x05, 0x18, 0x7e, 0x01, 0x18,
        0x20, 0x19, 0x0e, 0x10, 0x08, 0xa1, 0x01, 0xa2,
        0x01, 0x04, 0x20, 0x50, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x06, 0x1a, 0x5f, 0x5a,
        0x3e, 0x13, 0x18, 0x7d, 0x48, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47, 0x48
      };

      ticket_face.reset(abor_decode_start(t_face, sizeof(t_face)));
      REQUIRE(ticket_face != nullptr);
      REQUIRE(abor_check_type(ticket_face.get(), ABOR_BSTR));

      THEN("it can be parsed as COSE structure and decrypted") {
        cose_obj_t *result;
        const uint8_t *raw = abor_get_bytes(ticket_face.get());
        size_t raw_len = abor_get_sequence_length(ticket_face.get());

        REQUIRE(cose_parse(raw, raw_len, &result) == COSE_OK);
        REQUIRE(result != nullptr);
        object.reset(result);

        REQUIRE(object->buckets[COSE_UNPROTECTED].length == 16);
        REQUIRE(memcmp(object->buckets[COSE_UNPROTECTED].data, t_face + 7, 16) == 0);

        cose_result_t res =
          cose_decrypt(object.get(), nullptr, 0, buf, &buflen,
                       [](const char *, size_t, cose_mode_t, void *) {
                         return &rs_key;
                       },
                       nullptr);

        REQUIRE(res == COSE_OK);
        REQUIRE(buflen == sizeof(decrypted_t_face));
        REQUIRE(memcmp(buf, decrypted_t_face, buflen) == 0);
      }
    }

    WHEN("The ticket face contains an array as scope") {
      ticket_face.reset(abor_decode_start(buf, buflen));
      REQUIRE(ticket_face != nullptr);
      REQUIRE(abor_check_type(ticket_face.get(), ABOR_MAP));

      std::unique_ptr<abor_decoder_t, Deleter> scope;
      scope.reset(abor_mapget_int(ticket_face.get(), DCAF_TICKET_SCOPE));
      REQUIRE(scope != nullptr);
      REQUIRE(abor_check_type(scope.get(), ABOR_ARRAY));

      THEN("It can be parsed as AIF") {
        dcaf_aif_t *result;
        REQUIRE(dcaf_aif_parse(scope.get(), &result) == DCAF_OK);
        REQUIRE(result != nullptr);
        aif.reset(result);
      }
    }

    WHEN("The payload is comprised of invalid CBOR") {
      dcaf_ticket_request_t *result;

      // FIXME: As of version 4.3, coap_pdu_parse() is in libcoap's internal API 
      // REQUIRE(coap_pdu_parse(COAP_PROTO_UDP,
      //                        coap_data, sizeof(coap_data) - 1,
      //                        coap_pdu.get()) > 0);

      THEN("the dcaf_parse_ticket_request returns DCAF_OK") {
        dcaf_result_t res;

        /* Switch off debug logs temporarily to avoid cluttering the
         * logs with forced error messages. */
        test_log_off();
        res = dcaf_parse_ticket_request(NULL, coap_pdu.get(), &result);
        test_log_on();

        REQUIRE(res == DCAF_OK);
        REQUIRE(result != nullptr);
        treq.reset(result);
      }
    }
  }
}
