/*
 * dcaf_int.h -- internal declarations for libdcaf
 *
 * Copyright (C) 2015-2020 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2020 Stefanie Gerdes <gerdes@tzi.org>
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
#include "dcaf_base64.h"
#include "dcaf_mem.h"
#include "dcaf_coap.h"
#include "state.h"

/**
 * The type for the locally-generated unique transaction
 * identifier. */
typedef uint8_t dcaf_transaction_id_t[DCAF_DEFAULT_TOKEN_SIZE];

typedef struct dcaf_host_t dcaf_host_t;

struct dcaf_host_t {
  char *s;
  size_t length;
};

struct dcaf_transaction_t {
  dcaf_transaction_t *next;
  dcaf_host_t aud;              /* contents of the audience parameter */
  coap_endpoint_t *local_interface;
  coap_address_t remote;
  coap_proto_t proto;           /**< transport used for initial request */
  coap_block_t block;
  dcaf_response_handler_t response_handler;
  dcaf_error_handler_t error_handler;
  dcaf_application_handler_t application_handler;
  int flags;
  dcaf_transaction_id_t tid;
  coap_pdu_t *pdu;
  dcaf_state_t state;
};

#ifdef CONFIG_DCAF_SERVER
#define DCAF_SERVER CONFIG_DCAF_SERVER
#endif

#ifdef CONFIG_DCAF_CLIENT
#define DCAF_CLIENT CONFIG_DCAF_CLIENT
#endif

#ifdef CONFIG_DCAF_CLIENT_AND_SERVER
#ifndef CONFIG_DCAF_SERVER
#define DCAF_SERVER 1
#endif
#ifndef CONFIG_DCAF_CLIENT
#define DCAF_CLIENT 1
#endif
#endif

#ifdef CONFIG_DCAF_AM
#define DCAF_AM CONFIG_DCAF_AM
#endif

struct dcaf_context_t {
  coap_context_t *coap_context;
  coap_address_t am_address;
  coap_uri_t *am_uri;
  void *app;
  int flags;

  /** Wait time until a transaction is considered failed. This value
   * is specified in milliseconds. A value of 0 means no timeout. The
   * default value is 90000. */
  unsigned int timeout_ms;

  dcaf_transaction_t *transactions;
  dcaf_keystore_t *keystore;

  /* FIXME: include only if DCAF_AM != 0 */
  dcaf_get_ticket_cb get_ticket;
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

/**
 * The validity option supported by the DCAF client. Allowed values
 * are 1, 2, and 3, respectively.
 */
#ifndef DCAF_CLIENT_VALIDITY_OPTION
#define DCAF_CLIENT_VALIDITY_OPTION (1U)
#endif /* DCAF_CLIENT_VALIDITY_OPTION */

#ifndef DCAF_AM_ENCRYPT_TICKET_FACE
/** If set to 1, the ticket face will be encrypted */
#define DCAF_AM_ENCRYPT_TICKET_FACE (1U)
#endif /* DCAF_AM_ENCRYPT_TICKET_FACE */

/**
 * When DCAF_TEST_MODE_ACCEPT is set to a value != 0, SAM will accept
 * all ticket requests. This mode is for testing only and therefore
 * will usually be disabled.
 */
#ifndef DCAF_TEST_MODE_ACCEPT
#define DCAF_TEST_MODE_ACCEPT (0U)
#endif /* DCAF_TEST_MODE_ACCEPT */

/**
 * When DCAF_PRETTY_PRINT_CBOR is set to 1, code for pretty-printing
 * CBOR payloads will be included (requires cbor2pretty.rb in $PATH).
 */
#ifndef DCAF_PRETTY_PRINT_CBOR
#define DCAF_PRETTY_PRINT_CBOR (1U)
#endif /* DCAF_PRETTY_PRINT_CBOR */

#define DCAF_KEY_STATIC    0x0001
#define DCAF_KEY_HAS_DATA  0x0002

#ifndef DCAF_MAX_KID_SIZE
#define DCAF_MAX_KID_SIZE  (32)
#endif /* DCAF_MAX_KID_SIZE */

#ifndef DCAF_MAX_KEY_SIZE
#define DCAF_MAX_KEY_SIZE  (32)
#endif /* DCAF_MAX_KEY_SIZE */

struct dcaf_key_t {
  dcaf_key_type type;
  uint8_t kid[DCAF_MAX_KID_SIZE]; /**< The key id as known by our AM. */
  size_t kid_length;         /**< The length of kid in bytes. */
  unsigned int flags;
  uint8_t data[DCAF_MAX_KEY_SIZE];  /**< The actual key data. */
  size_t length;             /**< The key length in bytes. */
};

#ifndef DCAF_MAX_STRING
#define DCAF_MAX_STRING    (128)
#endif /* DCAF_MAX_STRING */

struct dcaf_ticket_t {
  struct dcaf_ticket_t *next;
  unsigned long seq;
  dcaf_time_t ts;               /**< time stamp */
  uint32_t remaining_time;      /**< remaining ticket lifetime */
  dcaf_aif_t *aif;              /**< authorization information */
  dcaf_key_t *key;              /**< key structure */

  /**
   * If set, this field identifies the CoAP session this ticket is
   * associated with. */
  void *session;
};

/* deprecated tickets */
struct dcaf_dep_ticket_t {
  struct dcaf_dep_ticket_t *next;
  unsigned long seq;           /**< The sequence number of the ticket. */
  dcaf_time_t ts;              /**< The timestamp to which the
				  remaining time refers */
  uint32_t remaining_time;      /**< The time in seconds until the
				  ticket becomes invalid */
};

/** The maximum number of bytes in the audience field. */
#define DCAF_MAX_AUDIENCE_SIZE DCAF_MAX_STRING

/** The maximum number of bytes in a nonce. */
#define DCAF_MAX_NONCE_SIZE 8

/** The maximum number of bytes in the audience field. */
#define DCAF_MAX_AS_HINT_SIZE DCAF_MAX_STRING

/* Information received by a ticket request */
struct dcaf_ticket_request_t {
  char aud[DCAF_MAX_AUDIENCE_SIZE + 1]; /**< addressed audience */
  uint8_t snc[DCAF_MAX_NONCE_SIZE];     /**< server nonce */
  size_t snc_length;
  char as_hint[DCAF_MAX_AS_HINT_SIZE + 1];  /**< AS creation hint */

  /** The flags field contains additional options for controlling the
   * ticket creation. Currently, the only option to set is
   * AM_INCLUDE_PROFILE to include the ace_profile parameter. */
  int flags;
  dcaf_aif_t *aif;                  /**< requested permissions */
};

#define AM_INCLUDE_PROFILE 0x01

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
    uint32_t timer; /* Time in seconds. Must be incremented over time
		   until a certain value is reached where the
		   nonce+timer are removed. */
  }validity_value;
};

/**
 * Retrieves the dcaf context object associated with a session. Note
 * that the session must have been created by dcaf to ensure that the
 * application data associated with the underlying CoAP context is a
 * valid dcaf_context_t structure.
 *
 * @param session A CoAP session created by the DCAF library.
 * @return        A pointer to the associated DCAF context or NULL.
 */
dcaf_context_t *dcaf_get_dcaf_context_from_session(const coap_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* _DCAF_INT_H_ */
