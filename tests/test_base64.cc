/*
 * test_base64.cc -- Base64 encoder/decoder
 *
 * Copyright (C) 2020 Olaf Bergmann <bergmann@tzi.org>
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

struct test_vector {
  const char *src;
  size_t srclen;
  const char *result;
  size_t resultlen;
};

static const test_vector testdata[] =
  {
   /* test vectors from RFC 4648 */
   { "", 0, "", 0 },
   { "f", 1, "Zg==", 4 },
   { "fo", 2, "Zm8=", 4 },
   { "foo", 3, "Zm9v", 4 },
   { "foob", 4, "Zm9vYg==", 8 },
   { "fooba", 5, "Zm9vYmE=", 8 },
   { "foobar", 6, "Zm9vYmFy", 8 }
};

#define MAX_TEST_BUF_SIZE 1024

template<unsigned int n> void do_encode(void) {
  GIVEN("A base64 test vector #" + std::to_string(n + 1)) {
    const struct test_vector &v = testdata[n];
    uint8_t buf[MAX_TEST_BUF_SIZE];
    size_t buflen = sizeof(buf);
    bool result;

    WHEN("The string encoded as base64") {
      result = dcaf_base64_encode(buf, &buflen,
                                  reinterpret_cast<const uint8_t *>(v.src), v.srclen);
      REQUIRE(result == true);

      THEN("the output buffer holds the encoded data") {
        REQUIRE(buflen == v.resultlen);
        REQUIRE(memcmp(buf, v.result, v.resultlen) == 0);
      }
    }
  }
}

/* The following two template functions are used to generate a series
 * of subsequently numbered test runs for the test vectors. Call with
 * any n >= 0.
 */
template<unsigned int n> void generate_encode_test(void) {
  generate_encode_test<n - 1>();
  do_encode<n>();
}

template<> void generate_encode_test<0>(void) {
  do_encode<0>();
}

SCENARIO( "Base64 encoding", "[base64]" ) {

  generate_encode_test<sizeof(testdata)/sizeof(testdata[0]) - 1>();
}

template<unsigned int n> void do_decode(void) {
  GIVEN("A base64 test vector #" + std::to_string(n + 1)) {
    const struct test_vector &v = testdata[n];
    uint8_t buf[MAX_TEST_BUF_SIZE];
    size_t buflen = sizeof(buf);
    bool result;

    WHEN("The string decoded from base64") {
      result = dcaf_base64_decode(buf, &buflen,
                                  reinterpret_cast<const uint8_t *>(v.result), v.resultlen);
      REQUIRE(result == true);

      THEN("the output buffer holds the decoded data") {
        REQUIRE(buflen == v.srclen);
        REQUIRE(memcmp(buf, v.src, v.srclen) == 0);
      }
    }
  }
}

/* The following two template functions are used to generate a series
 * of subsequently numbered test runs for the test vectors.  Call with
 * any n >= 0.
 */
template<unsigned int n> void generate_decode_test(void) {
  generate_decode_test<n - 1>();
  do_decode<n>();
}

template<> void generate_decode_test<0>(void) {
  do_decode<0>();
}

SCENARIO( "Base64 decoding", "[base64]" ) {

  generate_decode_test<sizeof(testdata)/sizeof(testdata[0]) - 1>();
}
