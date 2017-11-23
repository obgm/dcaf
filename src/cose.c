/*
 * cose.c -- definitions from COSE (RFC 8152)
 *
 * Copyright (C) 2017 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include "dcaf/cose.h"

bool cose_encrypt0(const dcaf_crypto_param_t *params,
                   const uint8_t *message, size_t message_len,
                   const uint8_t *extaad, size_t extaad_len,
                   uint8_t *result, size_t *result_len) {
  const char encrypt0_cbor_string[] = "\x68""Encrypt0";
  const size_t encrypt0_length = sizeof(encrypt0_cbor_string) - 1;
  (void)extaad;
  (void)extaad_len;

  return true;
}

