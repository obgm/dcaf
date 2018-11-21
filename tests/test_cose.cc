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

#include <cn-cbor/cn-cbor.h>

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"

#include "test.hh"
#include "catch.hpp"

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
      res = cose_decrypt(object.get(), nullptr, 0, buf, &buflen,
                         [](const char *, size_t, cose_mode_t, void *) {
                           static const dcaf_key_t key = {
                             (dcaf_key_type)COSE_AES_CCM_16_64_128,
			     {}, 0,
			     0, /* flags */
                             { 0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 },
			     16
                           };
                           return &key;
                         },
                         nullptr);

      THEN("decryption is successful") {
        REQUIRE(res == COSE_OK);

        /* check contents using memcmp() */
        REQUIRE(buflen == sizeof(a5_plaintext));
        REQUIRE(memcmp(buf, a5_plaintext, sizeof(a5_plaintext)) == 0);
      }
    }

    WHEN("cose_decrypt() is called with key == NULL") {
      buflen = sizeof(buf);
      res = cose_decrypt(object.get(), nullptr, 0, buf, &buflen,
                         [](const char *, size_t, cose_mode_t, void *) {
                           return static_cast<const dcaf_key_t *>(nullptr);
                         },
                         nullptr);

      THEN("result is COSE_TYPE_ERROR ") {
        REQUIRE(res == COSE_TYPE_ERROR);
        REQUIRE(buflen == 0);
      }
    }

    WHEN("cose_decrypt() is called with key == 0xffff") {
      buflen = sizeof(buf);
      res = cose_decrypt(object.get(), nullptr, 0, buf, &buflen,
                         [](const char *, size_t, cose_mode_t, void *) {
                           static const dcaf_key_t key = {
                             (dcaf_key_type)COSE_AES_CCM_16_64_128,
			     {}, 0,
			     0, /* flags */
                             { 0xff, 0xff },
			     2
                           };
                           return &key;
                         },
                         nullptr);

      THEN("result is COSE_DECRYPT_ERROR ") {
        REQUIRE(res == COSE_DECRYPT_ERROR);
        REQUIRE(buflen == 0);
      }
    }
  }
}

SCENARIO( "RFC 8152 Example C.4.1", "[C.4.1]" ) {
  static std::unique_ptr<cose_obj_t, Deleter> object;

  GIVEN("COSE_Encrypt0 from RFC 8152, Appendix C.4.1") {
    uint8_t raw[] = {
      0xD0, 0x83, 0x43, 0xA1, 0x01, 0x0A, 0xA1, 0x05,
      0x4D, 0x89, 0xF5, 0x2F, 0x65, 0xA1, 0xC5, 0x80,
      0x93, 0x3B, 0x52, 0x61, 0xA7, 0x8C, 0x58, 0x1C,
      0x59, 0x74, 0xE1, 0xB9, 0x9A, 0x3A, 0x4C, 0xC0,
      0x9A, 0x65, 0x9A, 0xA2, 0xE9, 0xE7, 0xFF, 0xF1,
      0x61, 0xD3, 0x8C, 0xE7, 0x1C, 0xB4, 0x5C, 0xE4,
      0x60, 0xFF, 0xB5, 0x69
    };
    uint8_t reference[] = { /* "This is the content." */
      0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
      0x74, 0x68, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x74,
      0x65, 0x6e, 0x74, 0x2e
    };

    WHEN("The COSE strucuture is parsed") {
      uint8_t buf[1024];
      size_t buflen;
      cose_obj_t *result;
      cose_result_t res;

      res = cose_parse(raw, sizeof(raw), &result);

      REQUIRE(res == COSE_OK);
      object.reset(result);

      THEN("it can be decrypted") {
        buflen = sizeof(buf);
        res = cose_decrypt(object.get(), nullptr, 0, buf, &buflen,
                           [](const char *, size_t, cose_mode_t, void *) {
                             static const dcaf_key_t key = {
                               (dcaf_key_type)COSE_AES_CCM_16_64_128,
			       {}, 0,
			       0, /* flags */
                               { 0x84, 0x9B, 0x57, 0x86, 0x45, 0x7C, 0x14, 0x91,
                                 0xBE, 0x3A, 0x76, 0xDC, 0xEA, 0x6C, 0x42, 0x71
                               },
			       16
                             };
                             return &key;
                           },
                           nullptr);

        REQUIRE(res == COSE_OK);

        /* check contents using memcmp() */
        REQUIRE(buflen == sizeof(reference));
        REQUIRE(memcmp(buf, reference, buflen) == 0);
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
      res = cose_decrypt(object.get(), nullptr, 0, buf, &buflen,
                         [](const char *, size_t, cose_mode_t mode, void *) {
                           static const dcaf_key_t key = {
                             (dcaf_key_type)COSE_AES_CCM_16_64_128,
			     {}, 0,
			     0, /* flags */
                             { 0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 },
			     16
                           };
                           REQUIRE(mode == COSE_MODE_DECRYPT);
                           return &key;
                         },
                         nullptr);

      THEN("decryption is successful") {
        REQUIRE(res == COSE_OK);

        /* check contents using memcmp() */
        // REQUIRE(buflen == sizeof(a5_plaintext));
        // REQUIRE(memcmp(buf, a5_plaintext, sizeof(a5_plaintext)) == 0);
      }
    }
  }
}

SCENARIO("cose_obj_t serialization", "[serialize]") {
  static std::unique_ptr<cose_obj_t, Deleter> object;

  const uint8_t ref[] = {
    0xD0, 0x83, 0x46, 0xA1, 0x0C, 0x43, 0x61, 0x62,
    0x63, 0x80, 0x40
  };
  const uint8_t ref2[] = {
    0x83, 0x59, 0x01, 0x4f, 0x59, 0x01, 0x4a, 0x12,
    0x34, 0x56, 0x78, 0x25, 0xe9, 0xd3, 0x11, 0x56,
    0x20, 0xc6, 0x86, 0xab, 0x82, 0x57, 0x23, 0x57,
    0x81, 0x25, 0x8a, 0x2c, 0x21, 0xfb, 0x6e, 0x30,
    0x45, 0x38, 0x83, 0xe1, 0xb3, 0xa4, 0xc1, 0x5b,
    0x71, 0x66, 0x13, 0x49, 0xb4, 0x61, 0x94, 0xce,
    0x58, 0x64, 0x11, 0x6c, 0xef, 0x83, 0xb8, 0xb8,
    0xd0, 0xe4, 0x8e, 0xa8, 0x52, 0x6b, 0x76, 0x84,
    0x03, 0xf8, 0xab, 0x50, 0x3a, 0xec, 0x45, 0xab,
    0xcb, 0xfd, 0xff, 0xb5, 0xeb, 0x86, 0x34, 0x2e,
    0x3c, 0xb3, 0x3c, 0xde, 0x64, 0x73, 0xbe, 0xca,
    0xf5, 0xfd, 0x39, 0xf2, 0xba, 0x42, 0x02, 0xe0,
    0xc6, 0xff, 0x61, 0x54, 0x6c, 0xc6, 0x08, 0xd1,
    0x1e, 0x07, 0xca, 0xe9, 0x06, 0x1e, 0x71, 0x98,
    0x91, 0x34, 0x9d, 0x30, 0xa1, 0xe9, 0x28, 0xea,
    0xc5, 0x59, 0x58, 0x88, 0xd2, 0x37, 0x70, 0xe8,
    0xdb, 0x25, 0xe9, 0xd3, 0x11, 0x56, 0x20, 0xc6,
    0x86, 0xab, 0x82, 0x57, 0x23, 0x57, 0x81, 0x25,
    0x8a, 0x2c, 0x21, 0xfb, 0x6e, 0x30, 0x45, 0x38,
    0x83, 0xe1, 0xb3, 0xa4, 0xc1, 0x5b, 0x71, 0x66,
    0x13, 0x49, 0xb4, 0x61, 0x94, 0xce, 0x58, 0x64,
    0x11, 0x6c, 0xef, 0x83, 0xb8, 0xb8, 0xd0, 0xe4,
    0x8e, 0xa8, 0x52, 0x6b, 0x76, 0x84, 0x03, 0xf8,
    0xab, 0x50, 0x3a, 0xec, 0x45, 0xab, 0xcb, 0xfd,
    0xff, 0xb5, 0xeb, 0x86, 0x34, 0x2e, 0x3c, 0xb3,
    0x3c, 0xde, 0x64, 0x73, 0xbe, 0xca, 0xf5, 0xfd,
    0x39, 0xf2, 0xba, 0x42, 0x02, 0xe0, 0xc6, 0xff,
    0x61, 0x54, 0x6c, 0xc6, 0x08, 0xd1, 0x1e, 0x07,
    0xca, 0xe9, 0x06, 0x1e, 0x71, 0x98, 0x91, 0x8a,
    0x79, 0x0f, 0x0d, 0x87, 0xe1, 0x36, 0xf9, 0xc1,
    0x96, 0xf2, 0x72, 0x4d, 0x35, 0x8e, 0xaf, 0xc2,
    0x86, 0x83, 0x73, 0xd6, 0xb1, 0x92, 0x59, 0xad,
    0x7f, 0x10, 0x36, 0x3d, 0xaf, 0x0c, 0xab, 0xb0,
    0x04, 0x07, 0xc9, 0x95, 0x26, 0x3b, 0x0e, 0x7b,
    0x6c, 0xcf, 0x40, 0x89, 0xe0, 0x9f, 0x62, 0x3d,
    0x34, 0x63, 0x8c, 0xb0, 0x40, 0x20, 0xf8, 0x9e,
    0x49, 0x54, 0xc5, 0xfd, 0x54, 0x9e, 0xe5, 0xe6,
    0x42, 0x7d, 0xd1, 0xe5, 0x73, 0x4a, 0x76, 0xfd,
    0x02, 0x06, 0x93, 0x72, 0x72, 0x1e, 0x31, 0x62,
    0x92, 0x01, 0x63, 0x73, 0x29, 0x2c, 0x40, 0xf3,
    0x55, 0x16, 0xd4, 0xb1, 0xf9, 0x5f, 0xe4, 0x34,
    0xb8, 0xb9, 0xb3, 0x86, 0xfb, 0x23, 0xde, 0xbc,
    0xa1, 0x0c, 0x59, 0x80, 0x40
    };
  uint8_t buf[1032];
  size_t buflen = 0;

  GIVEN("a non-empty cose_obj_t structure for COSE_Encrypt0") {
    cose_result_t res;

    object.reset(cose_obj_new());

    REQUIRE(object.get() != nullptr);

    cose_set_bucket(object.get(), COSE_PROTECTED, cn_cbor_map_create(nullptr));
    cn_cbor_mapput_int(object.get()->buckets[COSE_PROTECTED],
                       12,
                       cn_cbor_data_create((const uint8_t *)"abc",
                                           3, nullptr),
                       nullptr);
    cose_set_bucket(object.get(), COSE_UNPROTECTED,
                    cn_cbor_array_create(nullptr));
    cose_set_bucket(object.get(), COSE_DATA,
                    cn_cbor_data_create((const uint8_t *)"", 0, nullptr));

    WHEN("cose_serialize() is called on that object") {
      buflen = sizeof(buf);
      res = cose_serialize(object.get(), 0, buf, &buflen);

      REQUIRE(res == COSE_OK);

      THEN("The result matches h'83436061628040'") {
        REQUIRE(buflen == sizeof(ref) - 1);
        REQUIRE(memcmp(buf, ref + 1, buflen) == 0);
      }
    }

    WHEN("cose_serialize() is called to create a tagged object") {
      object.get()->type = COSE_ENCRYPT0;
      buflen = sizeof(buf);
      res = cose_serialize(object.get(), COSE_TAGGED, buf, &buflen);

      REQUIRE(res == COSE_OK);

      THEN("The result matches the tag 16 (COSE_Encrypt0)") {
        REQUIRE(memcmp(buf, ref, sizeof(ref)) == 0);
      }
    }
  }


  GIVEN("a cose_obj_t structure with >256 bytes in the protected bucket") {
    cose_result_t res;

    object.reset(cose_obj_new());

    REQUIRE(object.get() != nullptr);

    cose_set_bucket(object.get(), COSE_PROTECTED,
                    cn_cbor_map_create(nullptr));
    cn_cbor_mapput_int(object.get()->buckets[COSE_PROTECTED],
                       12,
                       cn_cbor_data_create((const uint8_t *)"\x12\x34\x56\x78\x25\xE9\xD3\x11\x56\x20\xC6\x86\xAB\x82\x57\x23\x57\x81\x25\x8A\x2C\x21\xFB\x6E\x30\x45\x38\x83\xE1\xB3\xA4\xC1\x5B\x71\x66\x13\x49\xB4\x61\x94\xCE\x58\x64\x11\x6C\xEF\x83\xB8\xB8\xD0\xE4\x8E\xA8\x52\x6B\x76\x84\x03\xF8\xAB\x50\x3A\xEC\x45\xAB\xCB\xFD\xFF\xB5\xEB\x86\x34\x2E\x3C\xB3\x3C\xDE\x64\x73\xBE\xCA\xF5\xFD\x39\xF2\xBA\x42\x02\xE0\xC6\xFF\x61\x54\x6C\xC6\x08\xD1\x1E\x07\xCA\xE9\x06\x1E\x71\x98\x91\x34\x9D\x30\xA1\xE9\x28\xEA\xC5\x59\x58\x88\xD2\x37\x70\xE8\xDB\x25\xE9\xD3\x11\x56\x20\xC6\x86\xAB\x82\x57\x23\x57\x81\x25\x8A\x2C\x21\xFB\x6E\x30\x45\x38\x83\xE1\xB3\xA4\xC1\x5B\x71\x66\x13\x49\xB4\x61\x94\xCE\x58\x64\x11\x6C\xEF\x83\xB8\xB8\xD0\xE4\x8E\xA8\x52\x6B\x76\x84\x03\xF8\xAB\x50\x3A\xEC\x45\xAB\xCB\xFD\xFF\xB5\xEB\x86\x34\x2E\x3C\xB3\x3C\xDE\x64\x73\xBE\xCA\xF5\xFD\x39\xF2\xBA\x42\x02\xE0\xC6\xFF\x61\x54\x6C\xC6\x08\xD1\x1E\x07\xCA\xE9\x06\x1E\x71\x98\x91\x8A\x79\x0F\x0D\x87\xE1\x36\xF9\xC1\x96\xF2\x72\x4D\x35\x8E\xAF\xC2\x86\x83\x73\xD6\xB1\x92\x59\xAD\x7F\x10\x36\x3D\xAF\x0C\xAB\xB0\x04\x07\xC9\x95\x26\x3B\x0E\x7B\x6C\xCF\x40\x89\xE0\x9F\x62\x3D\x34\x63\x8C\xB0\x40\x20\xF8\x9E\x49\x54\xC5\xFD\x54\x9E\xE5\xE6\x42\x7D\xD1\xE5\x73\x4A\x76\xFD\x02\x06\x93\x72\x72\x1E\x31\x62\x92\x01\x63\x73\x29\x2C\x40\xF3\x55\x16\xD4\xB1\xF9\x5F\xE4\x34\xB8\xB9\xB3\x86\xFB\x23\xDE\xBC\xAE\x80\x40",
                                           330, nullptr),
                       nullptr);
    cose_set_bucket(object.get(), COSE_UNPROTECTED,
                    cn_cbor_array_create(nullptr));
    cose_set_bucket(object.get(), COSE_DATA,
                    cn_cbor_data_create((const uint8_t *)"", 0, nullptr));

    WHEN("object is serialized") {
      object.get()->type = COSE_ENCRYPT0;
      buflen = sizeof(buf);
      res = cose_serialize(object.get(), 0, buf, &buflen);

      REQUIRE(res == COSE_OK);

      THEN("The result is a valid CBOR structure") {
        REQUIRE(memcmp(buf, ref2, sizeof(ref2)) == 0);
      }
    }
  }
}

SCENARIO("Creation of COSE_Encrypt0", "[cose]") {
  static std::unique_ptr<dcaf_key_t, Deleter> key;
  static std::unique_ptr<cn_cbor, Deleter> cbor;
  static std::unique_ptr<cose_obj_t, Deleter> object;
  static uint8_t buf[1032];
  size_t buflen = 0;

  GIVEN("an AES-128 key and sample data") {
    const uint8_t key_data[] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t data[] = {
      0xA3, 0x03, 0x05, 0x01, 0x04, 0x20, 0x58, 0x20,
      0x66, 0x84, 0x52, 0x3A, 0xB1, 0x73, 0x37, 0xF1,
      0x73, 0x50, 0x0E, 0x57, 0x28, 0xC6, 0x28, 0x54,
      0x7C, 0xB3, 0x7D, 0xFE, 0x68, 0x44, 0x9C, 0x65,
      0xF8, 0x85, 0xD1, 0xB7, 0x3B, 0x49, 0xEA, 0xE1
    };
    size_t data_len = sizeof(data);
    const uint8_t encrypted[] = { /* the reference data */
      0x83, 0x43, 0xa1, 0x01, 0x0a, 0xa1, 0x05, 0x4d,
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x58, 0x30, 0xb5,
      0x37, 0xb1, 0x89, 0x57, 0x29, 0xa2, 0xa2, 0x3c,
      0x13, 0x61, 0x9d, 0x2c, 0x47, 0x29, 0x29, 0x90,
      0x50, 0x0a, 0x75, 0x5e, 0xeb, 0x59, 0xb2, 0x50,
      0x4c, 0x83, 0xa4, 0xe4, 0x16, 0x57, 0x7e, 0x2d,
      0xd0, 0x9e, 0xff, 0xee, 0xe5, 0x4d, 0x99, 0xd7,
      0x07, 0x97, 0x19, 0x6a, 0x7c, 0x66, 0x25
    };

    dcaf_key_t *k= dcaf_new_key(DCAF_AES_128);
    cose_result_t res;

    REQUIRE(k != nullptr);
    key.reset(k);

    REQUIRE(key.get()->length == 16);

    REQUIRE(dcaf_set_key(key.get(), key_data, sizeof(key_data)));
    REQUIRE(memcmp(key.get()->data, key_data, sizeof(key_data)) == 0);

    WHEN("cose_encrypt0 is called") {
      cose_obj_t *tmp = nullptr;
      res = cose_encrypt0(COSE_AES_CCM_16_64_128, key.get(),
                          nullptr, 0, /* no external aad */
                          data, &data_len,
                          &tmp);
      REQUIRE(res == COSE_OK);
      REQUIRE(tmp != nullptr);

      object.reset(tmp);

      THEN("content can be serialized") {
        buflen = sizeof(buf);
        res = cose_serialize(object.get(), 0, buf, &buflen);
        REQUIRE(res == COSE_OK);
        REQUIRE(buflen > 0);

        dcaf_log(DCAF_LOG_DEBUG, "COSE_Encrypt0:\n");
        dcaf_debug_hexdump(buf, buflen);

        REQUIRE(memcmp(buf, encrypted, sizeof(encrypted)) == 0);
      }
    }
#if 0
    WHEN("COSE_Encrypt0 was succesfully created") {
      REQUIRE(cbor.get() != nullptr);

      THEN("it can be parsed") {
        cose_obj_t *result;
        res = cose_parse(buf, buflen, &result);

        REQUIRE(res == COSE_OK);
        REQUIRE(result != nullptr);
        object.reset(result);
      }
    }

    WHEN("COSE_Encrypt0 was succesfully parsed") {
      REQUIRE(object.get() != nullptr);

      THEN("it can be decrypted") {
        buflen = sizeof(buf);
        res = cose_decrypt(object.get(), nullptr, 0, buf, (size_t *)&buflen,
                           [](const char *, size_t, cose_mode_t mode, void *) {
                           // static const dcaf_key_t key = {
                           //   (dcaf_key_type)COSE_AES_CCM_16_64_128, 0,
                           //   sizeof(key_data),
                           //   (uint8_t *)"abc\x04\x05\x06\a\b\t\n\v\f\r\x0E\x0F\x10"
                           // };
                             REQUIRE(mode == COSE_MODE_DECRYPT);
                             return static_cast<const dcaf_key_t *>(key.get());
                           },
                           nullptr);
        REQUIRE(res == COSE_OK);
      }
    }
#endif
  }
}
