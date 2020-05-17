/*
 * dcaf_crypto_mbedtls.c -- MbedTLS implementation for DCAF crypto operations
 *
 * Copyright (C) 2020 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifdef COAP_DTLS_MBEDTLS
#include <mbedtls/cipher.h>
#include <mbedtls/md.h>

#include "dcaf/dcaf_crypto.h"
#include "dcaf/dcaf_int.h"

#ifndef MBEDTLS_CIPHER_MODE_AEAD
#error need MBEDTLS_CIPHER_MODE_AEAD, please enable MBEDTLS_CCM_C
#endif /* MBEDTLS_CIPHER_MODE_AEAD */

#ifdef MBEDTLS_ERROR_C
#include <mbedtls/error.h>
#endif /* MBEDTLS_ERROR_C */

/* The struct algs and the function get_alg() are used to determine
 * which cipher types function to use for creating the required cipher suite
 * object.
 */
static struct algs {
  dcaf_key_type alg;
  mbedtls_cipher_type_t cipher_type;
} ciphers[] = {
  { DCAF_AES_128, MBEDTLS_CIPHER_AES_128_CCM },
  { DCAF_AES_256, MBEDTLS_CIPHER_AES_256_CCM }
};
static inline int
get_alg(dcaf_key_type alg) {
  int idx;
  for (idx = 0; (size_t)idx < sizeof(ciphers)/sizeof(struct algs); idx++) {
    if (ciphers[idx].alg == alg)
      return idx;
  }
  dcaf_log(DCAF_LOG_DEBUG, "cipher not found\n");
  return -1;
}

#ifdef MBEDTLS_ERROR_C
#define C(Func) do {                                            \
  int c_tmp = (int)(Func);                                      \
  if (c_tmp != 0) {                                             \
    char error_buf[32];                                         \
    mbedtls_strerror(c_tmp, error_buf, sizeof(error_buf));      \
    dcaf_log(DCAF_LOG_ERR, "mbedtls: %s\n", error_buf);         \
    goto error;                                                 \
  }                                                             \
} while(0);
#else /* !MBEDTLS_ERROR_C */
#define C(Func) do {                                             \
  int c_tmp = (int)(Func);                                       \
  if (c_tmp != 0) {                                              \
    dcaf_log(DCAF_LOG_ERR, "mbedtls: %d\n", tmp);                \
    goto error;                                                  \
  }                                                              \
} while(0);
#endif /* !MBEDTLS_ERROR_C */

/**
 * Initializes the cipher context @p ctx. On success, this function
 * returns true and @p ctx must be released by the caller using
 * mbedtls_ciper_free(). */
static bool
setup_cipher_context(mbedtls_cipher_context_t *ctx,
                     dcaf_key_type dcaf_alg,
                     const uint8_t *key_data, size_t key_length,
                     mbedtls_operation_t mode) {
  const mbedtls_cipher_info_t *cipher_info;
  int tmp;

  tmp = get_alg(dcaf_alg);
      
  mbedtls_cipher_init(ctx);

  cipher_info = mbedtls_cipher_info_from_type(ciphers[tmp].cipher_type);
  if (!cipher_info) {
    dcaf_log(DCAF_LOG_CRIT, "dcaf_crypto: cannot get cipher info\n");
    return false;
  }

  C(mbedtls_cipher_setup(ctx, cipher_info));
  C(mbedtls_cipher_setkey(ctx, key_data, 8 * key_length, mode));
                                                                                   
  /* On success, the cipher context is released by the caller. */
  return true;
error:
  mbedtls_cipher_free(ctx);
  return false;
}

bool
dcaf_encrypt(const dcaf_crypto_param_t *params,
             const uint8_t *data, size_t data_len,
             const uint8_t *aad, size_t aad_len,
             uint8_t *result, size_t *max_result_len) {
  mbedtls_cipher_context_t ctx;
  const dcaf_aes_ccm_t *ccm;
  unsigned char tag[16];
  int ret = false;
  size_t result_len = *max_result_len;

  assert(params != NULL);

  if (!params) {
    return false;
  }
  ccm = &params->params.aes;

  if (!setup_cipher_context(&ctx, params->alg, ccm->key->data, ccm->key->length,
                            MBEDTLS_ENCRYPT)) {
    return false;
  }

  C(mbedtls_cipher_auth_encrypt(&ctx,
                                    ccm->nonce, 15 - ccm->l,  /* iv */
                                    aad, aad_len,             /* ad */
                                    data, data_len,           /* input */
                                    result, &result_len,      /* output */
                                    tag, ccm->tag_len         /* tag */
                                ));

  /* check if buffer is sufficient to hold tag */
  if ((result_len + ccm->tag_len) > *max_result_len) {
    dcaf_log(DCAF_LOG_ERR, "dcaf_encrypt: buffer too small\n");
    goto error;
  }
  /* append tag to result */
  memcpy(result + result_len, tag, ccm->tag_len);
  *max_result_len = result_len + ccm->tag_len;
  ret = true;
 error:
  mbedtls_cipher_free(&ctx);
  return ret;  
}

bool
dcaf_decrypt(const dcaf_crypto_param_t *params,
             const uint8_t *data, size_t data_len,
             const uint8_t *aad, size_t aad_len,
             uint8_t *result, size_t *max_result_len) {
  mbedtls_cipher_context_t ctx;
  const dcaf_aes_ccm_t *ccm;
  const unsigned char *tag;
  int ret = false;
  size_t result_len = *max_result_len;

  assert(params != NULL);

  if (!params) {
    return false;
  }
  ccm = &params->params.aes;

  if (!setup_cipher_context(&ctx, params->alg, ccm->key->data, ccm->key->length,
                            MBEDTLS_DECRYPT)) {
    return false;
  }

  if (data_len < ccm->tag_len) {
    dcaf_log(DCAF_LOG_ERR, "dcaf_decrypt: invalid tag length\n");
    goto error;
  }

  tag = data + data_len - ccm->tag_len;
  C(mbedtls_cipher_auth_decrypt(&ctx,
                                ccm->nonce, 15 - ccm->l,  /* iv */
                                aad, aad_len,             /* ad */
                                data, data_len - ccm->tag_len, /* input */
                                result, &result_len,      /* output */
                                tag, ccm->tag_len         /* tag */
                                ));

  *max_result_len = result_len;
  ret = true;
 error:
  mbedtls_cipher_free(&ctx);
  return ret;
}

bool
dcaf_hmac(const dcaf_crypto_param_t *params,
          const uint8_t *data, size_t data_len,
          uint8_t *result, size_t *max_result_len) {
  mbedtls_md_context_t ctx;
  int ret = false;
  const int use_hmac = 1;
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  if (*max_result_len < (size_t)mbedtls_md_get_size(md_info)) {
    dcaf_log(DCAF_LOG_ERR, "dcaf_hmac: output buffer too small\n");
    return false;
  }

  mbedtls_md_init(&ctx);  
  C(mbedtls_md_setup(&ctx, md_info, use_hmac));

  C(mbedtls_md_hmac_starts(&ctx, params->params.key->data, params->params.key->length));
  C(mbedtls_md_hmac_update(&ctx, (const unsigned char *)data, data_len));
  C(mbedtls_md_hmac_finish(&ctx, result));

  *max_result_len = (size_t)mbedtls_md_get_size(md_info);
  ret = true;
 error:
  mbedtls_md_free(&ctx);
  return ret;
}
#else /* !COAP_DTLS_MBEDTLS */
/* make compilers happy that do not like empty modules */
static inline void
dummy(void) {
}
#endif /* COAP_DTLS_MBEDTLS */

