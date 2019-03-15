/*
 * dcaf_crypto_tinydtls.c -- tinydtls implementation for DCAF crypto operations
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifdef COAP_DTLS_TINYDTLS
#include "dcaf/dcaf_crypto.h"
#include "dcaf/dcaf_int.h"

bool
dcaf_encrypt(const dcaf_crypto_param_t *params,
             const uint8_t *data, size_t data_len,
             const uint8_t *aad, size_t aad_len,
             uint8_t *result, size_t *max_result_len) {
  (void)params;
  (void)data;
  (void)data_len;
  (void)aad;
  (void)aad_len;
  (void)result;
  (void)max_result_len;

  /* FIXME */

  return false;
}

bool
dcaf_decrypt(const dcaf_crypto_param_t *params,
	     const uint8_t *data, size_t data_len,
	     const uint8_t *aad, size_t aad_len,
	     uint8_t *result, size_t *max_result_len) {
  (void)params;
  (void)data;
  (void)data_len;
  (void)aad;
  (void)aad_len;
  (void)result;
  (void)max_result_len;

  /* FIXME */

  return false;
}

bool
dcaf_hmac(const dcaf_crypto_param_t *params,
          const uint8_t *data, size_t data_len,
          uint8_t *result, size_t *max_result_len) {
  (void)params;
  (void)data;
  (void)data_len;
  (void)result;
  (void)max_result_len;

  /* FIXME */

  return false;
}
#else /* !COAP_DTLS_TINYDTLS */
/* make compilers happy that do not like empty modules */
static inline void
dummy(void) {
}
#endif /* COAP_DTLS_TINYDTLS */

