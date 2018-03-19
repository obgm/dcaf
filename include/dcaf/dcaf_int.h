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
#include "dcaf_mem.h"

#ifdef __cplusplus
extern "C" {
#ifdef EMACS_NEEDS_A_CLOSING_BRACKET
}
#endif
#endif

#include <cn-cbor/cn-cbor.h>

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
  /* dcaf_state_t state; */
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

#define DCAF_KEY_STATIC    0x0001
#define DCAF_KEY_HAS_DATA  0x0002

#define DCAF_MAX_KEY_SIZE  32
typedef struct dcaf_key_t {
  dcaf_key_type type;
  unsigned int flags;
  size_t length;
  uint8_t data[DCAF_MAX_KEY_SIZE];
} dcaf_key_t;

typedef unsigned long dcaf_time_t;

struct dcaf_authz_t {
  dcaf_mediatype_t mediatype;
  dcaf_result_t code;           /**< encoded response */
  dcaf_aif_t *aif;
  dcaf_key_t *key;              /**< key structure */
  dcaf_time_t ts;               /**< time stamp */
  unsigned long lifetime;       /**< ticket lifetime */
};

typedef struct dcaf_ticket_t {
  struct dcaf_ticket_t *next;

  uint8_t *kid;                 /**< The key id as known by our AM. */
  size_t kid_length;            /**< The length of kid in bytes. */

  uint8_t *verifier;            /**< The actual key data. */
  size_t verifier_length;       /**< The key length in bytes. */

  /* FIXME: dcaf_authz_t... */
}  dcaf_ticket_t;

dcaf_authz_t *dcaf_new_authz(void);

#ifdef __cplusplus
}
#endif

#endif /* _DCAF_INT_H_ */
