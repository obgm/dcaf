/*
 * dcaf_crypto.h -- wrapper for DCAF-related crypto operations
 *
 * Copyright (C) 2017 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_CRYPTO_H_
#define _DCAF_CRYPTO_H_ 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dcaf/dcaf_key.h"

typedef dcaf_key_type dcaf_alg_t;

typedef struct dcaf_aes_ccm_t {
  dcaf_key_t *key;
  uint8_t *nonce;
  size_t nonce_len;
  uint8_t tag_len;
  uint8_t l;
} dcaf_aes_ccm_t;

typedef struct dcaf_crypto_param_t {
  dcaf_alg_t alg;
  union {
    dcaf_aes_ccm_t aes;
    dcaf_key_t *key;
  } params;
} dcaf_crypto_param_t;

bool dcaf_encrypt(const dcaf_crypto_param_t *params,
                  const uint8_t *data, size_t data_len,
                  const uint8_t *aad, size_t aad_len,
                  uint8_t *result, size_t *max_result_len);

bool dcaf_decrypt(const dcaf_crypto_param_t *params,
                  const uint8_t *data, size_t data_len,
                  const uint8_t *aad, size_t add_len,
                  uint8_t *result, size_t *max_result_len);

bool dcaf_hmac(const dcaf_crypto_param_t *params,
               const uint8_t *data, size_t data_len,
               uint8_t *result, size_t *max_result_len);

#endif /* _DCAF_CRYPTO_H_ */

