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

SCENARIO( "Parse textual AIF representation", "[scope]" ) {
  static std::unique_ptr<dcaf_aif_t, Deleter> aif;
  static std::unique_ptr<abor_decoder_t, Deleter> abd;

  GIVEN("A CBOR string with method and resource") {
    const uint8_t cbor_str[] = { 0x6e, 'G', 'E', 'T', ' ', '/', 's', 'o',
                                 'm', 'e', 't', 'h', 'i', 'n', 'g' };
    abd.reset(abor_decode_start(cbor_str, sizeof(cbor_str)));

    REQUIRE(abd != nullptr);

    WHEN("The string is parsed as AIF") {
      dcaf_result_t res;
      dcaf_aif_t *result;

      res = dcaf_aif_parse_string(abd.get(), &result);
      aif.reset(result);

      THEN("the result is DCAF_OK and a valid AIF object is created") {

        REQUIRE(res == DCAF_OK);
        REQUIRE(aif.get() != nullptr);
        REQUIRE(aif.get()->perm.methods == 0x01);
        REQUIRE(aif.get()->perm.resource_len == strlen("/something"));
        REQUIRE(memcmp(aif.get()->perm.resource,
                       "/something",
                       aif.get()->perm.resource_len) == 0);
      }
    }
  }
}

SCENARIO( "Parse cbor AIF representation", "[aif]" ) {
  static std::unique_ptr<dcaf_aif_t, Deleter> aif;
  static std::unique_ptr<abor_encoder_t, Deleter> abc;
  static std::unique_ptr<abor_decoder_t, Deleter> abd;

  static const uint8_t cbor_arr[] = { 0x82, 0x6a, '/', 's', 'o', 'm', 'e', 't',
                                      'h', 'i', 'n', 'g', 0x01 };
  
  GIVEN("A CBOR AIF representation") {

    abd.reset(abor_decode_start(cbor_arr, sizeof(cbor_arr)));

    REQUIRE(abd != nullptr);

    WHEN("The string is parsed as AIF") {
      dcaf_result_t res;
      dcaf_aif_t *result;

      res = dcaf_aif_parse(abd.get(), &result);
      aif.reset(result);

      THEN("the result is DCAF_OK and a valid AIF object is created") {

        REQUIRE(res == DCAF_OK);
        REQUIRE(aif.get() != nullptr);
        REQUIRE(aif.get()->perm.methods == 0x01);
        REQUIRE(aif.get()->perm.resource_len == strlen("/something"));
        REQUIRE(memcmp(aif.get()->perm.resource,
                       "/something",
                       aif.get()->perm.resource_len) == 0);
      }
    }

    WHEN("The parsed AIF is converted to CBOR") {
      uint8_t buf[1024];
      REQUIRE(aif.get() != nullptr);

      abc.reset(abor_encode_start(buf, sizeof(buf)));
      REQUIRE(abc != nullptr);

      THEN("This should result in a CBOR AIF representation") {
        size_t length;
        REQUIRE(dcaf_aif_to_cbor(aif.get(), abc.get()));

        length = abor_encode_finish(abc.get());
        abc.release();

        REQUIRE(length == sizeof(cbor_arr));
        REQUIRE(memcmp(buf, cbor_arr, length) == 0);
      }
    }
  }
}

