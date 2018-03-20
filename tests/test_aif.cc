/*
 * test_aif.cc -- DCAF authorization information parser
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

#include "test.hh"
#include "catch.hpp"

SCENARIO( "Parse taxtual AIF representation", "[scope]" ) {
  static std::unique_ptr<dcaf_aif_t, Deleter> aif;
  static std::unique_ptr<cn_cbor, Deleter> cbor;

  GIVEN("A CBOR string with method and resource") {
#define AIF_METHOD "GET"
#define AIF_RESOURCE "/something"
    cn_cbor *cbor_str =
      cn_cbor_string_create(AIF_METHOD " " AIF_RESOURCE, NULL);

    REQUIRE(cbor_str != nullptr);
    cbor.reset(cbor_str);

    WHEN("The string is parsed as AIF") {
      dcaf_result_t res;
      dcaf_aif_t *result;

      res = dcaf_aif_parse(cbor.get(), &result);
      aif.reset(result);

      THEN("the result is DCAF_OK and a valid AIF object is created") {

        REQUIRE(res == DCAF_OK);
        REQUIRE(aif.get() != nullptr);
        REQUIRE(aif.get()->perm.methods == 0x01);
        REQUIRE(aif.get()->perm.resource_len == strlen(AIF_RESOURCE));
        REQUIRE(memcmp(aif.get()->perm.resource,
                       AIF_RESOURCE,
                       aif.get()->perm.resource_len) == 0);
      }
    }
  }
}
