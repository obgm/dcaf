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
#include "state.h"

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
  dcaf_state_t state;
};

struct dcaf_context_t {
  coap_context_t *coap_context;
  coap_address_t am_address;
  coap_uri_t *am_uri;
  void *app;
  int flags;
  dcaf_transaction_t *transactions;
  dcaf_keystore_t *keystore;
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
#define DCAF_MAX_SERVER_TIMEOUT 10 /* time in seconds that the server keeps the nonce when using validity option 3 */

#ifndef DCAF_AM_ENCRYPT_TICKET_FACE
/** If set to 1, the ticket face will be encrypted */
#define DCAF_AM_ENCRYPT_TICKET_FACE (1U)
#endif /* DCAF_AM_ENCRYPT_TICKET_FACE */

#define DCAF_KEY_STATIC    0x0001
#define DCAF_KEY_HAS_DATA  0x0002

#define DCAF_MAX_KID_SIZE  8
#define DCAF_MAX_KEY_SIZE  32
struct dcaf_key_t {
  dcaf_key_type type;
  uint8_t kid[DCAF_MAX_KID_SIZE]; /**< The key id as known by our AM. */
  size_t kid_length;         /**< The length of kid in bytes. */
  unsigned int flags;
  uint8_t data[DCAF_MAX_KEY_SIZE];  /**< The actual key data. */
  size_t length;             /**< The key length in bytes. */
};

#define DCAF_MAX_STRING    128

struct dcaf_ticket_t {
  struct dcaf_ticket_t *next;
  unsigned long seq;
  dcaf_time_t ts;               /**< time stamp */
  uint remaining_time;          /**< remaining ticket lifetime */
  dcaf_aif_t *aif;              /**< authorization information */
  dcaf_key_t *key;              /**< key structure */
};

/* deprecated tickets */
struct dcaf_dep_ticket_t {
  struct dcaf_dep_ticket_t *next;
  unsigned long seq;           /**< The sequence number of the ticket. */
  dcaf_time_t ts;              /**< The timestamp to which the
				  remaining time refers */
  uint remaining_time;         /**< The time in seconds until the
				  ticket becomes invalid */
};

#define DCAF_MAX_AUDIENCE_SIZE DCAF_MAX_STRING

/* Information received by a ticket request */
struct dcaf_ticket_request_t {
  char aud[DCAF_MAX_AUDIENCE_SIZE + 1]; /**< addressed audience */
  dcaf_aif_t *aif;                  /**< requested permissions */
};

#define DCAF_MAX_NONCE_SIZE 8

struct dcaf_nonce_t {
  uint8_t nonce[DCAF_MAX_NONCE_SIZE];
  size_t nonce_length;
  struct dcaf_nonce_t *next;
  /* timer or timestamp */
  enum {
    option_2=2,
    option_3
  }validity_type;
  union {
    dcaf_time_t dat; /* System time when SAM info message was sent. */
    uint timer; /* Time in seconds. Must be incremented over time
		   until a certain value is reached where the
		   nonce+timer are removed. */
  }validity_value;
};

#ifdef __cplusplus
}
#endif

#endif /* _DCAF_INT_H_ */
