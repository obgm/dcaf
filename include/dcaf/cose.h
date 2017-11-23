/*
 * cose.h -- definitions from COSE (RFC 8152)
 *
 * Copyright (C) 2017 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _COSE_H_
#define _COSE_H_ 1

#include <stdbool.h>
#include <stdint.h>

#include "dcaf/dcaf_crypto.h"

#define COSE_ALG                  1
#define COSE_CRIT                 2
#define COSE_CONTENT_TYPE         3
#define COSE_KID                  4
#define COSE_IV                   5
#define COSE_PARTIAL_IV           6
#define COSE_COUNTER_SIGNATURE    7

/* Key map labels */
#define COSE_KEY_KTY_SYMMETRIC    3
#define COSE_KEY_KTY              1
#define COSE_KEY_KID              2
#define COSE_KEY_ALG              3
#define COSE_KEY_OPS              4
#define COSE_KEY_BASE_IV          5

/* see https://tools.ietf.org/html/draft-ietf-ace-cwt-proof-of-possession */
#define CWT_COSE_KEY              1
#define CWT_ENCRYPTED_COSE_KEY    2
#define CWT_KID                   3

#define COSE_KEY_K    3

#define COSE_ALG_HS256  3

bool cose_encrypt0(const dcaf_crypto_param_t *params,
                   const uint8_t *message, size_t message_len,
                   const uint8_t *extaad, size_t extaad_len,
                   uint8_t *result, size_t *result_len);

#endif /* _COSE_H_ */

