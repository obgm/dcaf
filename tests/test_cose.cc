/*
 * test_cose.cc -- COSE unit tests for DCAF
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
#include "test_cose.hh"

#include "catch.hpp"

/* Helper structure to simplify deletion of COSE objects in smart
 * pointers. */
struct Deleter {
  void operator()(cose_obj_t *p) { cose_obj_delete(p); }
};

SCENARIO( "CWT Example 3.3", "[cwt]" ) {
  static std::unique_ptr<cose_obj_t, Deleter> object;

  GIVEN("A COSE_Encrypt0 structure") {
    uint8_t a5[] = {
      0xD0, 0x83, 0x43, 0xA1, 0x01, 0x0A, 0xA1, 0x05,
      0x4D, 0x63, 0x68, 0x98, 0x99, 0x4F, 0xF0, 0xEC,
      0x7B, 0xFC, 0xF6, 0xD3, 0xF9, 0x5B, 0x58, 0x30,
      0x05, 0x73, 0x31, 0x8A, 0x35, 0x73, 0xEB, 0x98,
      0x3E, 0x55, 0xA7, 0xC2, 0xF0, 0x6C, 0xAD, 0xD0,
      0x79, 0x6C, 0x9E, 0x58, 0x4F, 0x1D, 0x0E, 0x3E,
      0xA8, 0xC5, 0xB0, 0x52, 0x59, 0x2A, 0x8B, 0x26,
      0x94, 0xBE, 0x96, 0x54, 0xF0, 0x43, 0x1F, 0x38,
      0xD5, 0xBB, 0xC8, 0x04, 0x9F, 0xA7, 0xF1, 0x3F
    };

    uint8_t a5_plaintext[] = {
      0xA3, 0x03, 0x05, 0x01, 0x04, 0x20, 0x58, 0x20,
      0x66, 0x84, 0x52, 0x3A, 0xB1, 0x73, 0x37, 0xF1,
      0x73, 0x50, 0x0E, 0x57, 0x28, 0xC6, 0x28, 0x54,
      0x7C, 0xB3, 0x7D, 0xFE, 0x68, 0x44, 0x9C, 0x65,
      0xF8, 0x85, 0xD1, 0xB7, 0x3B, 0x49, 0xEA, 0xE1
    };
    
    uint8_t buf[1024];
    size_t buflen;
    cose_result_t res;

    WHEN("structure is parsed") {
      cose_obj_t *result;
      res = cose_parse(a5, sizeof(a5), &result);

      THEN("the result is COSE_OK") {
        REQUIRE(res == COSE_OK);
        object.reset(result);
      }
    }
    WHEN("cose_decrypt() is called with key 6162630405060708090a0b0c0d0e0f10") {
      buflen = sizeof(buf);
      res = cose_decrypt(object.get(), NULL, 0, buf, &buflen,
                         [](const char *, size_t, cose_mode_t) {
                           static const dcaf_key_t key = {
                             (dcaf_key_type)COSE_AES_CCM_16_64_128, 0,
                             16,
                             (uint8_t *)"abc\x04\x05\x06\a\b\t\n\v\f\r\x0E\x0F\x10" };
                           return &key;
                         });

      THEN("decryption is successful") {
        REQUIRE(res == COSE_OK);

        /* check contents using memcmp() */
        REQUIRE(buflen == sizeof(a5_plaintext));
        REQUIRE(memcmp(buf, a5_plaintext, sizeof(a5_plaintext)) == 0);
      }
    }

    WHEN("cose_decrypt() is called with key == NULL") {
      buflen = sizeof(buf);
      res = cose_decrypt(object.get(), NULL, 0, buf, &buflen,
                         [](const char *, size_t, cose_mode_t) {
                           return static_cast<const dcaf_key_t *>(nullptr);
                         });

      THEN("result is COSE_TYPE_ERROR ") {
        REQUIRE(res == COSE_TYPE_ERROR);
        REQUIRE(buflen == 0);
      }
    }    

    WHEN("cose_decrypt() is called with key == 0xffff") {
      buflen = sizeof(buf);
      res = cose_decrypt(object.get(), NULL, 0, buf, &buflen,
                         [](const char *, size_t, cose_mode_t) {
                           static const dcaf_key_t key = {
                             (dcaf_key_type)COSE_AES_CCM_16_64_128, 0,
                             2,
                             (uint8_t *)"\xff\xff" };
                           return &key;
                         });

      THEN("result is COSE_DECRYPT_ERROR ") {
        REQUIRE(res == COSE_DECRYPT_ERROR);
        REQUIRE(buflen == 0);
      }
    }    
  }
}



SCENARIO( "ACE-java CWT test", "[ace-java]" ) {
  static std::unique_ptr<cose_obj_t, Deleter> object;

  GIVEN("A COSE_Encrypt0 structure") {

    uint8_t raw[] = {
      0xd0, 0x83, 0x43, 0xa1, 0x01, 0x0a, 0xa1, 0x05,
      0x4d, 0xeb, 0x39, 0x1c, 0x86, 0xf5, 0x00, 0x00,
      0xac, 0xcf, 0x5a, 0x7f, 0x88, 0xbc, 0x58, 0xc0,
      0x17, 0x02, 0x08, 0x05, 0x05, 0x81, 0x62, 0xde,
      0x12, 0xba, 0x8d, 0x8d, 0xfa, 0xdb, 0xe7, 0xc5,
      0xca, 0x36, 0x6e, 0x27, 0x43, 0x1d, 0x79, 0xb3,
      0xc8, 0xfb, 0x71, 0xd3, 0x07, 0x05, 0x4b, 0xc9,
      0x63, 0x91, 0x20, 0xb8, 0x5f, 0xe0, 0xad, 0x4c,
      0x72, 0x49, 0xb5, 0x65, 0x7a, 0x22, 0x40, 0xf6,
      0x0a, 0xe2, 0x77, 0x92, 0x06, 0x24, 0x6f, 0x32,
      0xf7, 0xb2, 0x8a, 0xf3, 0xf0, 0x40, 0xd5, 0x2c,
      0x49, 0x2e, 0x1e, 0x47, 0xee, 0x26, 0xb8, 0xf7,
      0x48, 0x92, 0xc7, 0x21, 0xf3, 0xa1, 0x25, 0xbc,
      0x8f, 0xad, 0xd5, 0x49, 0x7a, 0xa7, 0x88, 0x0d,
      0xec, 0xf8, 0xd5, 0x3e, 0xbf, 0x16, 0x22, 0x4e,
      0x64, 0x3b, 0x4e, 0xf6, 0x14, 0x09, 0x8e, 0x79,
      0xe6, 0xe0, 0xd3, 0x82, 0xb8, 0xc3, 0x48, 0xb8,
      0x55, 0x4f, 0xaf, 0x78, 0xb3, 0x55, 0xdb, 0x45,
      0xff, 0x2d, 0xf7, 0x9f, 0xb6, 0xee, 0xfc, 0xbf,
      0x9b, 0xd2, 0x2d, 0xcf, 0x99, 0x49, 0xf9, 0x3b,
      0xf1, 0x66, 0xdc, 0x46, 0xb2, 0x93, 0x1d, 0x7b,
      0x1e, 0x3f, 0x84, 0x50, 0x6a, 0x6b, 0x3b, 0xa8,
      0x14, 0x7d, 0x40, 0xf5, 0x98, 0xac, 0x5d, 0xf0,
      0x3d, 0x6a, 0x11, 0x7c, 0xc5, 0x89, 0x6b, 0x4e,
      0xa7, 0x6d, 0xef, 0x9c, 0x5b, 0x2b, 0xce, 0x32,
      0x5d, 0x6f, 0x45, 0x65, 0xfe, 0xbe, 0x7f, 0x44,
      0x8b, 0x71, 0xc1, 0xf4, 0x43, 0x91, 0x4a, 0xb2,
    };

    /*
      {12: "r+/s/light rwx+/a/led w+/dtls",
       25: { -3: h'11D08F6392D63EAE3BCE7ECEB60AE15A127268B01A752069496A17EB21E741CC',
              3: -7,
             -2: h'62CC97F67756BC13E588DECF70B1341F495028C397DC8BDA4C16783428C59BC9',
              1: 2,
             -1: 1},
         3: "coap://light.example.com",
         4: 1444064944,
         5: 1443944944,
         6: 1443944944,
         1: "coap://as.example.com",
       7: h'0B71'}
    */
       
    uint8_t buf[1024];
    size_t buflen;
    cose_result_t res;

    WHEN("structure is parsed") {
      cose_obj_t *result;
      res = cose_parse(raw, sizeof(raw), &result);

      THEN("the result is COSE_OK") {
        REQUIRE(res == COSE_OK);
        object.reset(result);
      }
    }
    WHEN("cose_decrypt() is called with key 6162630405060708090a0b0c0d0e0f10") {
      buflen = sizeof(buf);
      res = cose_decrypt(object.get(), NULL, 0, buf, &buflen,
                         [](const char *, size_t, cose_mode_t mode) {
                           static const dcaf_key_t key = {
                             (dcaf_key_type)COSE_AES_CCM_16_64_128, 0,
                             16,
                             (uint8_t *)"abc\x04\x05\x06\a\b\t\n\v\f\r\x0E\x0F\x10"
                           };
                           REQUIRE(mode == COSE_MODE_DECRYPT);
                           return &key;
                         });

      THEN("decryption is successful") {
        REQUIRE(res == COSE_OK);

        /* check contents using memcmp() */
        // REQUIRE(buflen == sizeof(a5_plaintext));
        // REQUIRE(memcmp(buf, a5_plaintext, sizeof(a5_plaintext)) == 0);
      }
    }
  }
}
