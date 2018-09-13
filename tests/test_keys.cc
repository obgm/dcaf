/*
 * test_keys.cc -- DCAF key generation
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

SCENARIO( "DCAF key generator", "[keys]" ) {
  static std::unique_ptr<dcaf_key_t, Deleter> key;
  static std::unique_ptr<dcaf_ticket_t, Deleter> ticket;

  GIVEN("A new DCAF AES-128 key") {
    dcaf_key_t *k = dcaf_new_key(DCAF_AES_128);
    key.reset(k);


    WHEN("the PRNG sequence is 0, 1, 2, 3, ...") {
      THEN("dcaf_key_rnd(key) sets the key 000102030405060708090a0b0c0d0e0f") {
        uint8_t ref_key[] = {
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        REQUIRE(dcaf_key_rnd(key.get()));
        REQUIRE(key.get()->length == sizeof(ref_key));
        REQUIRE(memcmp(key.get()->data, ref_key, sizeof(ref_key)) == 0);
      }
    }
  }

  GIVEN("A new ticket object") {
    dcaf_ticket_t *a = dcaf_new_ticket(DCAF_AES_128,
                                       42, 1200, 600);
    ticket.reset(a);

    WHEN("the key component is NULL") {
      REQUIRE(ticket.get()->key == NULL);

      THEN("dcaf_create_verifier() creates a new random key") {
        uint8_t ref_key[] = {
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };

        REQUIRE(dcaf_create_verifier(NULL, ticket.get()) == DCAF_OK);
        REQUIRE(ticket.get()->key != NULL);
        REQUIRE(ticket.get()->key->length == sizeof(ref_key));
        REQUIRE(memcmp(ticket.get()->key->data, ref_key, sizeof(ref_key)) == 0);
      }
    }
  }
}
