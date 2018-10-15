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
#include "dcaf/utlist.h"

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

/* TODO: might want to use hash map on non-constrained systems. */
struct dcaf_keystore_t {
  struct dcaf_keystore_t *next;
#define DCAF_MAX_PEER_SIZE 32
  uint8_t peer[DCAF_MAX_PEER_SIZE];
  size_t peer_len;
  dcaf_key_t *key;
};

void
dcaf_add_key(dcaf_context_t *dcaf_context,
             const uint8_t *peer, size_t peer_len,
             dcaf_key_t *key) {
  /* FIXME: replace if already exists */
  /* FIXME: dcaf_alloc_type */
  dcaf_keystore_t *ks = coap_malloc(sizeof(dcaf_keystore_t));
  if (ks) {
    memset(ks, 0, sizeof(dcaf_keystore_t));
    ks->key = key;
    if (peer && (peer_len > 0) && (peer_len <= DCAF_MAX_PEER_SIZE)) {
      memcpy(ks->peer, peer, peer_len);
      ks->peer_len = peer_len;
    }
    LL_PREPEND(dcaf_context->keystore, ks);
  } else {
    dcaf_log(DCAF_LOG_WARNING, "cannot allocate new keystore object\n");
  }
}

static bool
kid_matches(const dcaf_key_t *key, const uint8_t *kid, size_t len) {
  if (key) {
    /* kid == NULL matches any kid. Otherwise, check if kids match. */
    return !kid || ((key->kid_length == len)
                    && ((len == 0)
                        || (memcmp(key->kid, kid, len) == 0)));
  }
  return false;
}

dcaf_key_t *
dcaf_find_key(dcaf_context_t *dcaf_context,
              const uint8_t *peer,
              size_t peer_length,
              const uint8_t *kid,
              size_t kid_length) {
  dcaf_keystore_t *ks;

  LL_FOREACH(dcaf_context->keystore, ks) {
    /* match kid only if peer is empty */
    if (!peer || (peer_length == 0)) {
      if (kid_matches(ks->key, kid, kid_length)) {
        return ks->key;
      }
    } else {
      /* Check kid only if peers match. Note that ks->peer is not
       * empty if peer_length == ks->peer_length is true. */
      if ((peer_length == ks->peer_len)
          && (memcmp(ks->peer, peer, ks->peer_len) == 0)) {
        if (kid_matches(ks->key, kid, kid_length)) {
          return ks->key;
        }
      }
    }
  }
  return NULL;
}
