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

#ifdef __cplusplus
extern "C" {
#ifdef EMACS_NEEDS_A_CLOSING_BRACKET
}
#endif
#endif

#include "aif.h"
#include "dcaf.h"
#include "dcaf_mem.h"
#include "dcaf_coap.h"

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

/**
 * The validity option supported by the DCAF server. Allowed values
 * are 1, 2, and 3, respectively. If option 1 is set, the ticket must
 * contain an iat field, options 2 and 3 require snc to be set which
 * must be copied from the SAM information message that was generated
 * by this server.
 */
#ifndef DCAF_SERVER_VALIDITY_OPTION
#define DCAF_SERVER_VALIDITY_OPTION (1U)
#endif /* DCAF_SERVER_VALIDITY_OPTION */

#define DCAF_KEY_STATIC    0x0001
#define DCAF_KEY_HAS_DATA  0x0002

#define DCAF_MAX_KEY_SIZE  32
struct dcaf_key_t {
  dcaf_key_type type;
  unsigned int flags;
  size_t length;
  uint8_t data[DCAF_MAX_KEY_SIZE];
};

#define DCAF_MAX_STRING    128

typedef unsigned long dcaf_time_t; 

struct dcaf_authz_t {
  dcaf_mediatype_t mediatype;
  dcaf_result_t code;           /**< encoded response */
  dcaf_aif_t *aif;
  dcaf_key_t *key;              /**< key structure */
  dcaf_time_t ts;               /**< time stamp */
  unsigned long lifetime;       /**< ticket lifetime */
};

struct dcaf_ticket_t {
  struct dcaf_ticket_t *next;
  uint64_t seq;

  uint8_t *kid;                 /**< The key id as known by our AM. */
  size_t kid_length;            /**< The length of kid in bytes. */

  uint8_t *verifier;            /**< The actual key data. */
  size_t verifier_length;       /**< The key length in bytes. */

  /* FIXME: dcaf_authz_t... */
};

struct dcaf_nonce_t {
  uint8_t nonce[8];
  size_t nonce_length;
  struct dcaf_nonce_t *next;
  /* timer or timestamp */
  enum {
    option_2=2,
    option_3
  }validity_type;
  union {
    dcaf_time_t dat; /* SAM info message sent at */
    uint timer;
  }validity_value;
};

dcaf_authz_t *dcaf_new_authz(void);

#ifdef __cplusplus
}
#endif

#endif /* _DCAF_INT_H_ */
