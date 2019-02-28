/*
 * dcaf_crypto_tinydtls.c -- tinydtls implementation for DCAF crypto operations
 *
 * Copyright (C) 2018-2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 *
 * Extended by Sara Stadler 2018/2019
 */

#ifdef COAP_DTLS_TINYDTLS
#include <crypto.h>

#include "dcaf/dcaf_crypto.h"
#include "dcaf/dcaf_int.h"

bool
dcaf_encrypt(const dcaf_crypto_param_t *params,
             const uint8_t *data, size_t data_len,
             const uint8_t *aad, size_t aad_len,
             uint8_t *result, size_t *max_result_len) {
  int num_bytes;
  const dcaf_aes_ccm_t *ccm;

  assert(params);

  if (params->alg != DCAF_AES_128) {
    dcaf_log(DCAF_LOG_DEBUG,
             "dcaf_encrypt: algorithm %d not supported\n",
             params->alg);
    return false;
  }

  ccm = &params->params.aes;
  if (*max_result_len < (data_len + ccm->tag_len)) {
    dcaf_log(DCAF_LOG_WARNING,
             "dcaf_encrypt: result buffer too small\n");
    return false;
  }

  num_bytes = dtls_encrypt(data, data_len,
                           result, ccm->nonce,
                           ccm->key->data, ccm->key->length,
                           aad, aad_len);
  if (num_bytes < 0) {
    return false;
  }
  *max_result_len = num_bytes;
  return true;
}

bool
dcaf_decrypt(const dcaf_crypto_param_t *params,
	     const uint8_t *data, size_t data_len,
	     const uint8_t *aad, size_t aad_len,
	     uint8_t *result, size_t *max_result_len) {
  int num_bytes;
  const dcaf_aes_ccm_t *ccm;

  assert(params);

  if (params->alg != DCAF_AES_128) {
    dcaf_log(DCAF_LOG_DEBUG,
             "dcaf_decrypt: algorithm %d not supported\n",
             params->alg);
    return false;
  }

  ccm = &params->params.aes;

  if ((*max_result_len + ccm->tag_len) < data_len) {
    dcaf_log(DCAF_LOG_WARNING,
             "dcaf_decrypt: result buffer too small\n");
    return false;
  }

  num_bytes = dtls_decrypt(data, data_len,
                           result, ccm->nonce,
                           ccm->key->data, ccm->key->length,
                           aad, aad_len);
  if (num_bytes < 0) {
    return false;
  }
  *max_result_len = num_bytes;
  return true;
}

bool
dcaf_hmac(const dcaf_crypto_param_t *params,
          const uint8_t *data, size_t data_len,
          uint8_t *result, size_t *max_result_len) {
  dtls_hmac_context_t hmac_context;
  const dcaf_key_t *key;
  int num_bytes;

  assert(params);

  if (params->alg != DCAF_HS256) {
    dcaf_log(DCAF_LOG_DEBUG,
             "dcaf_hmac: algorithm %d not supported\n",
             params->alg);
    return false;
  }
  key = params->params.key;

  if (*max_result_len < DTLS_SHA256_DIGEST_LENGTH) {
    dcaf_log(DCAF_LOG_WARNING,
             "dcaf_hmac: result buffer too small\n");
    return false;
  }
  dtls_hmac_init(&hmac_context, key->data, key->length);
  dtls_hmac_update(&hmac_context, data, data_len);
  num_bytes = dtls_hmac_finalize(&hmac_context, result);

  if (num_bytes != DTLS_SHA256_DIGEST_LENGTH) {
    return false;
  }
  *max_result_len = num_bytes;
  return true;
}

/**
 * Get the fingerprint from ASN1 certificate as hex string.
 */
char*
get_fingerprint_from_cert(const uint8_t *asn1_public_cert,
		size_t asn1_length) {
	(void)asn1_public_cert;
	(void) asn1_length;
	/* FIXME */
}
#else /* !COAP_DTLS_TINYDTLS */
/* make compilers happy that do not like empty modules */
static inline void
dummy(void) {
}
#endif /* COAP_DTLS_TINYDTLS */

