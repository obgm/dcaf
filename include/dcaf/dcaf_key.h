/*
 * dcaf_key.h -- wrapper for DCAF-related crypto operations
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_KEY_H_
#define _DCAF_KEY_H_ 1

#include <stdbool.h>
#include <stdint.h>

struct dcaf_key_t;
typedef struct dcaf_key_t dcaf_key_t;

typedef enum {
  DCAF_NONE = 0,
  DCAF_AES_128 = 1,             /**< AES-128-CCM */
  DCAF_AES_256 = 2,             /**< AES-256-CCM */
  DCAF_HS256 = 64               /**< HMAC-SHA256 */
} dcaf_key_type;

dcaf_key_t *dcaf_new_key(dcaf_key_type type);

void dcaf_delete_key(dcaf_key_t *key);

bool dcaf_key_rnd(dcaf_key_t *key);

#endif /* _DCAF_KEY_H_ */
