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
  if (key) {
    if (data_len > DCAF_MAX_KEY_SIZE) {
      dcaf_log(DCAF_LOG_ERR, "key '%.*s' too long (DCAF_MAX_KEY_SIZE=%d)\n",
               (int)data_len, data, DCAF_MAX_KEY_SIZE);
      return false;
    }
    memset(key->data, 0, DCAF_MAX_KEY_SIZE);
    key->length = data_len;
    if (data_len > 0) {
      memcpy(key->data, data, data_len);
    }
    return true;
  }
  return false;
}

bool
dcaf_set_kid(dcaf_key_t *key, const uint8_t *kid, size_t kid_len) {
  if (key) {
    if (kid_len > DCAF_MAX_KID_SIZE) {
      dcaf_log(DCAF_LOG_ERR, "kid '%.*s' too long (DCAF_MAX_KID_SIZE=%d)\n",
               (int)kid_len, kid, DCAF_MAX_KID_SIZE);
      return false;
    }
    memset(key->kid, 0, DCAF_MAX_KID_SIZE);
    key->kid_length = kid_len;
    if (kid_len > 0) {
      memcpy(key->kid, kid, kid_len);
    }
    return true;
  }
  return false;
}

/* TODO: might want to use hash map on non-constrained systems. */
struct dcaf_keystore_t {
  struct dcaf_keystore_t *next;
  coap_address_t peer;
  dcaf_key_t *key;
};

void
dcaf_add_key(dcaf_context_t *dcaf_context,
             const coap_address_t *peer,
             dcaf_key_t *key) {
  /* FIXME: replace if already exists */
  /* FIXME: dcaf_alloc_type */
  dcaf_keystore_t *ks = coap_malloc(sizeof(dcaf_keystore_t));
  if (ks) {
    memset(ks, 0, sizeof(dcaf_keystore_t));
    ks->key = key;
    if (peer) {
      coap_address_copy(&ks->peer, peer);
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
              const coap_address_t *peer,
              const uint8_t *kid,
              size_t kid_length) {
  dcaf_keystore_t *ks;

  LL_FOREACH(dcaf_context->keystore, ks) {
    /* match kid only if peer is empty */
    if (!peer) {
      if (kid_matches(ks->key, kid, kid_length)) {
        return ks->key;
      }
    } else {
      /* Check kid only if peers match. Note that ks->peer is not
       * empty if peer_length == ks->peer_length is true. */
      if (coap_address_equals(&ks->peer, peer)) {
        if (!kid || kid_matches(ks->key, kid, kid_length)) {
          return ks->key;
        }
      }
    }
  }
  return NULL;
}
