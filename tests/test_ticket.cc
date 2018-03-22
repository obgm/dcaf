/*
 * test_ticket.cc -- DCAF authorization ticket handling
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
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
  static std::unique_ptr<dcaf_authz_t, Deleter> authz;
  static std::unique_ptr<coap_pdu_t, Deleter> coap_pdu;
  static std::unique_ptr<coap_pdu_t, Deleter> coap_response;
  static std::unique_ptr<cn_cbor, Deleter> claim;
  static std::unique_ptr<cose_obj_t, Deleter> object;
  static bool coap_dtls = false;

  coap_response.reset(coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU));

  GIVEN("A ticket request") {
    coap_pdu_t request;

    uint8_t coap_data[] = {
      (COAP_DEFAULT_VERSION << 6) | (COAP_MESSAGE_NON << 4), /* TKL == 0 */
      COAP_REQUEST_POST, 0x12, 0x34, /* arbitray mid */
      (COAP_OPTION_CONTENT_FORMAT << 4) | 1, COAP_MEDIATYPE_APPLICATION_CBOR,
      COAP_PAYLOAD_START,
      0xa2, 0x03, 0x6d, 0x73, 0x2e, 0x65, 0x78, 0x61,
      0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67,
      0x0c, 0x82, 0x6c, 0x2f, 0x72, 0x65, 0x73, 0x74,
      0x72, 0x69, 0x63, 0x74, 0x65, 0x64, 0x31, 0x05
    };
    coap_pdu.reset(coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU));
    REQUIRE(coap_pdu.get() != nullptr);

    WHEN("The request is parsed") {
      coap_session_t session;
      dcaf_authz_t *result;
      session.context = dcaf_get_coap_context(dcaf_context());

      REQUIRE(coap_pdu_parse(COAP_PROTO_UDP,
                             coap_data, sizeof(coap_data),
                             coap_pdu.get()) > 0);

      THEN("the dcaf_parse_ticket_request returns DCAF_OK") {
        dcaf_result_t res;
        res = dcaf_parse_ticket_request(&session, coap_pdu.get(), &result);
        REQUIRE(res == DCAF_OK);
        REQUIRE(result != nullptr);
        authz.reset(result);
        REQUIRE(authz.get()->code == DCAF_OK);
      }
    }

    WHEN("A validated dcaf_authz_t structure is available") {
      coap_session_t session;
      session.context = dcaf_get_coap_context(dcaf_context());

      REQUIRE(authz.get() != nullptr);
      REQUIRE(authz.get()->code == DCAF_OK);

      THEN("a ticket grant can be created") {
        dcaf_set_ticket_grant(&session, authz.get(), coap_response.get());
        REQUIRE(coap_response.get()->code == COAP_RESPONSE_CODE(201));

        /* check Content-Format */
        REQUIRE(test_option_eq(coap_response.get(),
                               COAP_OPTION_CONTENT_FORMAT,
                               authz.get()->mediatype));

        /* check CBOR payload */
        size_t databuf_len;
        unsigned char *databuf;
        cn_cbor *data;
        REQUIRE(coap_get_data(coap_response.get(), &databuf_len, &databuf));

        data = cn_cbor_decode(databuf, databuf_len, nullptr);
        REQUIRE(data != nullptr);

        claim.reset(data);
      }
    }

    WHEN("A ticket grant was created") {
      REQUIRE(claim.get() != nullptr);

      THEN("The profile must be coap_dtls") {
        cn_cbor *profile = cn_cbor_mapget_int(claim.get(), ACE_CLAIM_PROFILE);
        REQUIRE(profile != nullptr);
        REQUIRE(profile->type == CN_CBOR_UINT);
        REQUIRE(profile->v.uint == ACE_PROFILE_DTLS);
        coap_dtls = true;
      }
    }

    WHEN("A ticket grant for coap_dtls is present") {
      REQUIRE(claim.get() != nullptr);
      REQUIRE(coap_dtls);

      THEN("The grant must contain a cnf claim with a symmetric key") {
        cn_cbor *cnf = cn_cbor_mapget_int(claim.get(), ACE_CLAIM_CNF);
        REQUIRE(cnf != nullptr);
        REQUIRE(cnf->type == CN_CBOR_MAP);

        cn_cbor *cwt_key = cn_cbor_mapget_int(cnf, CWT_COSE_KEY);
        REQUIRE(cwt_key != nullptr);
        REQUIRE(cwt_key->type == CN_CBOR_MAP);

        cn_cbor *kty = cn_cbor_mapget_int(cwt_key, COSE_KEY_KTY);
        REQUIRE(kty != nullptr);
        REQUIRE(kty->type == CN_CBOR_UINT);
        REQUIRE(kty->v.uint == COSE_KEY_KTY_SYMMETRIC);

        cn_cbor *k = cn_cbor_mapget_int(cwt_key, COSE_KEY_K);
        REQUIRE(k != nullptr);
        REQUIRE(k->type == CN_CBOR_BYTES);

        /* use the same not-so-random key sequence */
        uint8_t key[16];
        dcaf_prng(key, sizeof(key));

        REQUIRE(k->length == sizeof(key));
        REQUIRE(memcmp(k->v.bytes, key, k->length) == 0);
      }
    }

    WHEN("The grant contains a bstr-encoded access ticket") {
      REQUIRE(claim.get() != nullptr);

      cn_cbor *bstr = cn_cbor_mapget_int(claim.get(), ACE_CLAIM_ACCESS_TOKEN);
      REQUIRE(bstr != nullptr);
      REQUIRE(bstr->type == CN_CBOR_BYTES);

      THEN("It must contain an encrypted COSE_Key structure") {
        cose_obj_t *result;
        cose_result_t res =
          cose_parse(bstr->v.bytes, bstr->length, &result);
        REQUIRE(res == COSE_OK);
        REQUIRE(result != nullptr);
        object.reset(result);
      }
    }

    WHEN("An encrypted COSE_Key structure is contained in grant") {
      REQUIRE(object.get() != nullptr);

      /* the decrypted key must be the same as the key in the ticket face */
      THEN("It can be decrypted with RS's key") {
        uint8_t buf[1024];
        size_t buflen = sizeof(buf);
        cose_result_t res =
          cose_decrypt(object.get(), nullptr, 0, buf, &buflen,
                       [](const char *, size_t, cose_mode_t) {
                         static const dcaf_key_t key = {
                           (dcaf_key_type)COSE_AES_CCM_16_64_128, 0,
                           16,
                           { 0x52, 0x53, 0x27, 0x73, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x32, 0x33, 0x34, 0x35, 0x36 }
                         };
                         return &key;
                       });

        REQUIRE(res == COSE_OK);
      }
    }

    WHEN("The payload is comprised of invalid CBOR") {
      coap_session_t session;
      dcaf_authz_t *result;

      REQUIRE(coap_pdu_parse(COAP_PROTO_UDP,
                             coap_data, sizeof(coap_data) - 1,
                             coap_pdu.get()) > 0);

      THEN("the dcaf_parse_ticket_request returns DCAF_OK") {
        dcaf_result_t res;

        /* Switch off debug logs temporarily to avoid cluttering the
         * logs with forced error messages. */
        test_log_off();
        res = dcaf_parse_ticket_request(&session, coap_pdu.get(), &result);
        test_log_on();

        REQUIRE(res == DCAF_OK);
        REQUIRE(result != nullptr);
        authz.reset(result);
        REQUIRE(authz.get()->code == DCAF_ERROR_BAD_REQUEST);
      }
    }
  }
}
