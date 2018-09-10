/*
 * test_crypto.cc -- DCAF crypto function wrappers
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
#include "dcaf/dcaf_crypto.h"

#include "test.hh"
#include "catch.hpp"

SCENARIO( "AEAD decrypt", "[aead]" ) {

  GIVEN("An encrypted message, aad and a key") {
// 2.5.0 :049 > data.unpack("H*")
//  => ["a20c824c2f7265737472696374656431051819a101a201042050000102030405060708090a0b0c0d0e0f"] 
// 2.5.0 :050 > ciphertext.unpack("H*")
//  => ["d91821c442696865456143097389ec779e4aec1a6bef95a23445559a7deee9c78dd0ade62058014dfb64d59573846782710c"] 
    uint8_t ciphertext[] = {
      0xd9, 0x18, 0x21, 0xc4, 0x42, 0x69, 0x68, 0x65,
      0x45, 0x61, 0x43, 0x09, 0x73, 0x89, 0xec, 0x77,
      0x9e, 0x4a, 0xec, 0x1a, 0x6b, 0xef, 0x95, 0xa2,
      0x34, 0x45, 0x55, 0x9a, 0x7d, 0xee, 0xe9, 0xc7,
      0x8d, 0xd0, 0xad, 0xe6, 0x20, 0x58, 0x01, 0x4d,
      0xfb, 0x64, 0x0f, 0x6c, 0xd2, 0x03, 0x04, 0x63,
      0xda, 0x14
    };
    uint8_t aad[] = {
      0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70,
      0x74, 0x30, 0x43, 0xa1, 0x01, 0x0a, 0x40 
    };
    uint8_t nonce[] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c 
    };
    /* uint8_t key[] = { */
    /*   0x52, 0x53, 0x27, 0x73, 0x20, 0x73, 0x65, 0x63, */
    /*   0x72, 0x65, 0x74, 0x32, 0x33, 0x34, 0x35, 0x36 */
    /* }; */
    dcaf_key_t key = {
      (dcaf_key_type)COSE_AES_CCM_16_64_128,
      nullptr, 0,
      0, /* flags */
      16,
      { 0x52, 0x53, 0x27, 0x73, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x32, 0x33, 0x34, 0x35, 0x36 }
    };
    
    WHEN("dcaf_decrypt() is called") {
      uint8_t buf[1024];
      size_t buflen = sizeof(buf);
      dcaf_crypto_param_t params;
      memset(&params, 0, sizeof(params));
      params.alg = DCAF_AES_128;
      params.params.aes.key = &key;
      params.params.aes.nonce = nonce;
      params.params.aes.tag_len = 8;
      params.params.aes.l = 2;
      
      REQUIRE(dcaf_decrypt(&params, ciphertext, sizeof(ciphertext),
                           aad, sizeof(aad), buf, &buflen));

      THEN("The ciphertext is decrypted") {
        dcaf_debug_hexdump(buf, buflen);
        REQUIRE(true);
      }
    }
  }
}
