/*
 * dcaf_crypto_openssl.c -- OpenSSL implementation for DCAF crypto operations
 *
 * Copyright (C) 2017 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifdef BUILD_WITH_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "dcaf/dcaf_crypto.h"
#include "dcaf/dcaf_int.h"

bool
dcaf_encrypt(const dcaf_crypto_param_t *params,
             const uint8_t *data, size_t data_len,
             uint8_t *result, size_t *max_result_len) {
  const EVP_CIPHER *cipher;
  const dcaf_aes_ccm_t *ccm;
  int tmp;
  assert(params != NULL);

  if (!params || (params->alg != DCAF_AES_128)) {
    return false;
  }

  /* TODO: set evp_md depending on params->alg */
  cipher = EVP_aes_128_ccm();
  ccm = &params->params.aes;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                 
  EVP_CIPHER_CTX_init(ctx);
  EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, ccm->tag_len, NULL);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, ccm->l, NULL);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ccm->nonce_len, NULL);
  EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, ccm->nonce);
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  EVP_EncryptInit_ex(ctx, NULL, NULL, ccm->key->data, NULL);

  EVP_EncryptUpdate(ctx, result, max_result_len, data, data_len);
  EVP_EncryptFinal_ex(ctx, result + *max_result_len, &tmp);
  *max_result_len += tmp;

  /* retrieve the tag */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, ccm->tag_len,
                      result + *max_result_len);
  *max_result_len += ccm->tag_len;
  EVP_CIPHER_CTX_free(ctx);
  return true;
}

bool
dcaf_hmac(const dcaf_crypto_param_t *params,
          const uint8_t *data, size_t data_len,
          uint8_t *result, size_t *max_result_len) {
  unsigned int result_len;
  const EVP_MD *evp_md;

  assert(params);
  assert(data);
  assert(result);
  assert(max_result_len);

  result_len = *max_result_len;
  evp_md = EVP_sha256();
  /* TODO: set evp_md depending on params->alg */
  if (HMAC(evp_md, params->params.key->data,
           params->params.key->length, data, data_len, result, &result_len)) {
    *max_result_len = result_len;
    return true;
  }

  return false;
}
#else /* !BUILD_WITH_OPENSSL */
void
dummy(void) {
/* make compilers happy that do not like empty modules */
static inline void
dummy(void) {
}
#endif /* BUILD_WITH_OPENSSL */

