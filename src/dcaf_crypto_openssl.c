/*
 * dcaf_crypto_openssl.c -- OpenSSL implementation for DCAF crypto operations
 *
 * Copyright (C) 2017-2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifdef COAP_DTLS_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "dcaf/dcaf_crypto.h"
#include "dcaf/dcaf_int.h"

#define C(Func) if (1 != (Func)) { fprintf(stderr, "oops\n"); }
bool
dcaf_encrypt(const dcaf_crypto_param_t *params,
             const uint8_t *data, size_t data_len,
             const uint8_t *aad, size_t aad_len,
             uint8_t *result, size_t *max_result_len) {
  const EVP_CIPHER *cipher;
  const dcaf_aes_ccm_t *ccm;
  int tmp;
  int result_len = (int)(*max_result_len & INT_MAX);
  assert(params != NULL);

  if (!params || (params->alg != DCAF_AES_128)) {
    return false;
  }

  /* TODO: set evp_md depending on params->alg */
  ccm = &params->params.aes;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  cipher = EVP_aes_128_ccm();
                 
  /* EVP_CIPHER_CTX_init(ctx); */
  C(EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL));
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, ccm->l, NULL));
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 15 - ccm->l, NULL));
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, ccm->tag_len, NULL));
  C(EVP_EncryptInit_ex(ctx, NULL, NULL, ccm->key->data, ccm->nonce));
  /* C(EVP_CIPHER_CTX_set_padding(ctx, 0)); */

  C(EVP_EncryptUpdate(ctx, NULL, &result_len, NULL, data_len));
  int outl = 0;
  if (aad && (aad_len > 0)) {
  dcaf_log(DCAF_LOG_DEBUG, "aad\n");
  dcaf_debug_hexdump(aad, aad_len);
    C(EVP_EncryptUpdate(ctx, NULL, &result_len, aad, aad_len));
  }
  C(EVP_EncryptUpdate(ctx, result, &result_len, data, data_len));
  /* C(EVP_EncryptFinal_ex(ctx, result + result_len, &tmp)); */
  C(EVP_EncryptFinal_ex(ctx, result + result_len, &tmp));
  result_len += tmp;

  /* retrieve the tag */
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, ccm->tag_len,
                        result + result_len));

  *max_result_len = result_len + ccm->tag_len;
  EVP_CIPHER_CTX_free(ctx);
  return true;
}

bool
dcaf_decrypt(const dcaf_crypto_param_t *params,
             const uint8_t *data, size_t data_len,
             const uint8_t *aad, size_t aad_len,
             uint8_t *result, size_t *max_result_len) {
  const EVP_CIPHER *cipher;
  const dcaf_aes_ccm_t *ccm;
  int tmp;
  int len;
  //  int result_len = (int)(*max_result_len & INT_MAX);
  const uint8_t *tag;

  assert(params != NULL);

  if (!params || (params->alg != DCAF_AES_128)) {
    return false;
  }

  ccm = &params->params.aes;

  if (data_len < ccm->tag_len) {
    return false;
  } else {
    tag = data + data_len - ccm->tag_len;
    data_len -= ccm->tag_len;
  }
  
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  /* TODO: set evp_md depending on params->alg */
  cipher = EVP_aes_128_ccm();

  C(EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL));
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 15 - ccm->l, NULL));
  dcaf_debug_hexdump(tag, ccm->tag_len);
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, ccm->tag_len, (void *)tag));
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, ccm->l, NULL));
  /* C(EVP_CIPHER_CTX_set_padding(ctx, 0)); */
  C(EVP_DecryptInit_ex(ctx, NULL, NULL, ccm->key->data, ccm->nonce));

  C(EVP_DecryptUpdate(ctx, NULL, &len, NULL, data_len));
  if (aad && (aad_len > 0)) {
    C(EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len));
  }
  tmp = EVP_DecryptUpdate(ctx, result, &len, data, data_len);
  if (tmp > 0) {
    *max_result_len = len;
  } else {
    *max_result_len = 0;
  }
  EVP_CIPHER_CTX_free(ctx);
  return *max_result_len > 0;
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
#else /* !COAP_DTLS_OPENSSL */
/* make compilers happy that do not like empty modules */
static inline void
dummy(void) {
}
#endif /* COAP_DTLS_OPENSSL */

