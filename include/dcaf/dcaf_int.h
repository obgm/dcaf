/*
 * dcaf_int.h -- internal declarations for libdcaf
 *
 * Copyright (C) 2015-2016 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2016 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_INT_H_
#define _DCAF_INT_H_ 1

#include <coap/coap.h>
#include "dcaf.h"
#include "state.h"

struct dcaf_transaction_t {
  dcaf_transaction_t *next;
  coap_endpoint_t *local_interface;
  coap_address_t remote;
  coap_block_t block;
  dcaf_response_handler_t response_handler;
  dcaf_error_handler_t error_handler;
  int flags;
  coap_tid_t tid;
  coap_pdu_t *pdu;
  dcaf_state_t state;
};

struct dcaf_context_t {
  coap_context_t *coap_context;
  coap_address_t am_address;
  coap_uri_t *am_uri;
  void *app;
  int flags;
  dcaf_transaction_t *transactions;
};

typedef void *dcaf_aif_t;

typedef enum dcaf_key_type {
  DCAF_KEY_HMAC_SHA256 =   0,
  DCAF_KEY_HMAC_SHA384 =   1,
  DCAF_KEY_HMAC_SHA512 =   2,
  DCAF_KEY_DIRECT      = 129
} dcaf_key_type;

typedef struct dcaf_key_t {
  dcaf_key_type type;
  size_t length;
  uint8_t *data;
} dcaf_key_t;

typedef unsigned long dcaf_time_t;

struct dcaf_authz_t {
  dcaf_mediatype_t mediatype;
  dcaf_aif_t *aif;
  dcaf_key_t *key;              /**< key structure */
  dcaf_time_t ts;               /**< time stamp */
  unsigned long lifetime;       /**< ticket lifetime */
};

typedef enum dcaf_object_type {
  DCAF_CONTEXT = 1
} dcaf_object_type;

/* map the DCAF log function to libcoap's log function */
#define dcaf_log coap_log

#endif /* _DCAF_INT_H_ */
