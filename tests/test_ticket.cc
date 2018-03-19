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

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_prng.h"

#include "test.hh"
#include "catch.hpp"

SCENARIO( "DCAF ticket request", "[ticket]" ) {
  static std::unique_ptr<dcaf_authz_t, Deleter> authz;
  static std::unique_ptr<coap_pdu_t, Deleter> coap_pdu;
  
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
