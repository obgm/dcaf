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

#include "catch.hpp"

/* Helper structure to simplify deletion of COSE objects in smart
 * pointers. */
struct Deleter {
  void operator()(dcaf_key_t *p) { dcaf_delete_key(p); }
};

/* Generate deterministic "random" values. This function sets out to
 * the sequence 0, 1, 2, ... len-1.
 */
static void
rand_func(uint8_t *out, size_t len) {
  uint8_t n = 0;
  while(len--) {
    *out++ = n++;
  }
}

SCENARIO( "DCAF key generator", "[keys]" ) {
  static std::unique_ptr<dcaf_key_t, Deleter> key;

  GIVEN("A new DCAF AES-128 key") {
    dcaf_key_t *k = dcaf_new_key(DCAF_AES_128);
    key.reset(k);


    WHEN("the PRNG sequence is 0, 1, 2, 3, ...") {
      dcaf_set_prng(rand_func);

      THEN("dcaf_key_rnd(key) sets the key 000102030405060708090a0b0c0d0e0f") {
        uint8_t ref_key[] = {
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        REQUIRE(dcaf_key_rnd(key.get()));
        REQUIRE(key.get()->length == 16);
        REQUIRE(memcmp(key.get()->data, ref_key, key.get()->length) == 0);
      }
    }
  }
}
