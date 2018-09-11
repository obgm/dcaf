/*
 * dcaf_key.c -- DCAF key functions
 *
 * Copyright (C) 2015-2018 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2018 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <assert.h>
#include <stddef.h>

#include <cn-cbor/cn-cbor.h>

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_key.h"

dcaf_key_t *
dcaf_new_key(dcaf_key_type type) {
  dcaf_key_t *key = (dcaf_key_t *)dcaf_alloc_type(DCAF_KEY);

  if (key) {
    memset(key, 0, sizeof(dcaf_key_t));
    key->type = type;
  }
  return key;
}

void
dcaf_delete_key(dcaf_key_t *key) {
  dcaf_free_type(DCAF_KEY, key);
}

bool
dcaf_key_rnd(dcaf_key_t *key) {
  if (key) {
    key->length = 0;
    switch (key->type) {
    case DCAF_NONE:
      break;
    case DCAF_AES_128: key->length=16;
      break;
    case DCAF_AES_256: key->length=32;
      break;
    case DCAF_HS256: key->length=32;
      break;
    case DCAF_KID: key->length=DCAF_MAX_KID_SIZE;
      break;
    default:
      ;
    }
  }
  return key && key->length && dcaf_prng(key->data, key->length);
}

bool
dcaf_set_key(dcaf_key_t *key, const uint8_t *data, size_t data_len) {
  if (key && (data_len <= DCAF_MAX_KEY_SIZE)) {
    memset(key->data, 0, DCAF_MAX_KEY_SIZE);
    key->length = data_len;
    if (data_len > 0) {
      memcpy(key->data, data, data_len);
    }
    return true;
  }
  return false;
}
