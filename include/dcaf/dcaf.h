/*
 * dcaf.h -- main header file for libdcaf
 *
 * Copyright (C) 2015-2016 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2016 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_H_
#define _DCAF_H_ 1

#ifdef __cplusplus
extern "C" {
#ifdef EMACS_NEEDS_A_CLOSING_BRACKET
}
#endif
#endif

#define DCAF_AM_DEFAULT_PATH "authorize"

/** Default lifetime of a DCAF access ticket in seconds. */
#define DCAF_DEFAULT_LIFETIME       3600

typedef enum {
  DCAF_OK,
  DCAF_ERROR_OUT_OF_MEMORY,
  DCAF_ERROR_BUFFER_TOO_SMALL,
  DCAF_ERROR_INTERNAL_ERROR,
  DCAF_ERROR_BAD_REQUEST          = 0x10,
  DCAF_ERROR_UNAUTHORIZED         = 0x13,
  DCAF_ERROR_INVALID_TICKET       = 0x15,
  DCAF_ERROR_UNSUPPORTED_KEY_TYPE = 0x16
} dcaf_result_t;

#include "dcaf_coap.h"
#include "dcaf_address.h"
#include "dcaf_debug.h"
#include "dcaf_crypto.h"
#include "dcaf_key.h"
#include "dcaf_optlist.h"
#include "dcaf_prng.h"

#include "cose.h"
#include "cwt.h"

#define DCAF_TYPE_SAM   0
#define DCAF_TYPE_SAI   1
#define DCAF_TYPE_CAI   2
#define DCAF_TYPE_E     3
#define DCAF_TYPE_K     4
#define DCAF_TYPE_NONCE 5
#define DCAF_TYPE_L     6
#define DCAF_TYPE_G     7
#define DCAF_TYPE_F     8
#define DCAF_TYPE_V     9
#define DCAF_TYPE_A    10
#define DCAF_TYPE_D    11
#define DCAF_TYPE_N    12

enum dcaf_ticket_field {
  DCAF_TICKET_ISS             = CWT_CLAIM_ISS,
  DCAF_TICKET_AUD             = CWT_CLAIM_AUD,
  DCAF_TICKET_IAT             = CWT_CLAIM_IAT,
  DCAF_TICKET_CNF             = CWT_CLAIM_CNF,
  DCAF_TICKET_SCOPE           = 9,
  DCAF_TICKET_EXPIRES_IN      = 32,
  DCAF_TICKET_SNC             = 125,
  DCAF_TICKET_SEQ             = 126,
  DCAF_TICKET_DSEQ            = 127,
  DCAF_TICKET_DAT             = 128
  /* use cti instead of seq? */
};

typedef enum {
  DCAF_MEDIATYPE_DCAF_CBOR = 75,
  DCAF_MEDIATYPE_ACE_CBOR  = COAP_MEDIATYPE_APPLICATION_CBOR
} dcaf_mediatype_t;

#define  DCAF_MEDIATYPE_DCAF_CBOR_STRING "75"
#define  DCAF_MEDIATYPE_ACE_CBOR_STRING  "60"

/** Default configuration options for dcaf_initialize(). */
typedef struct dcaf_config_t {
  const char *host;    /**< Host name or IP address of the DCAF entity. */
  uint16_t coap_port;  /**< CoAP port number or 0 for default. */
  uint16_t coaps_port; /**< Port number for CoAP DTLS port or 0 for default.  */

  /**
   * URI path for configuring the default authorization manager.
   *
   * This is a zero-terminated string that denotes the URI path for
   * configuring the default authorization manager. It will be
   * registered as a resource with coap_context. */
  const char *am_uri;
} dcaf_config_t;

struct dcaf_context_t;
typedef struct dcaf_context_t dcaf_context_t;

#include "dcaf/dcaf_transaction.h"

#define DCAF_CONTEXT_RELEASE_AM_URI     0x02

/**
 * Creates a new DCAF context with the configuration given in @p
 * config. If @p config is NULL or config options are set to NULL
 * values, proper defaults will be used.
 *
 * @param config       Configuration options or NULL for defaults.
 */
dcaf_context_t *dcaf_new_context(const dcaf_config_t *config);

void dcaf_free_context(dcaf_context_t *context);

struct coap_context_t;
typedef struct coap_context_t coap_context_t;

coap_context_t *dcaf_get_coap_context(dcaf_context_t *context);
dcaf_context_t *dcaf_get_dcaf_context(coap_context_t *context);

void dcaf_set_app_data(dcaf_context_t *dcaf_context, void *data);

void *dcaf_get_app_data(dcaf_context_t *dcaf_context);

int dcaf_set_am_uri(dcaf_context_t *context,
                    const unsigned char *uri,
                    size_t uri_length);

coap_endpoint_t *dcaf_select_interface(dcaf_context_t *context,
                                       const coap_address_t *dst,
                                       int secure);

const coap_address_t *dcaf_get_am_address(dcaf_context_t *context);

/**
 * Checks if the given @p pdu is authorized in the context
 * of @p session. This function returns 1 on successful
 * authorization, 0 otherwise.
 *
 * @param session The active session where pdu was received.
 * @param pdu     The request or response to check.
 * @return 1 if @p pdu is authorized, 0 otherwise.
 */
int dcaf_is_authorized(const coap_session_t *session,
                       coap_pdu_t *pdu);

/**
 * Fills the given @p response with a payload that points to the
 * resource server's authorization manager. If no SAM information is
 * available (see dcaf_set_am_uri()), an empty 4.01 response will be
 * created.
 *
 * @param session The active session where @p request was received
 * @param mediatype The payload's desired format
 * @param response  A result parameter providing a pre-initialized
 *                  response.
 *
 * @return DCAF_OK on success, an error code otherwise.
 */
dcaf_result_t dcaf_set_sam_information(const coap_session_t *session,
                                       dcaf_mediatype_t mediatype,
                                       coap_pdu_t *response);

/**
 * Fills the given @p response with a payload that describes the
 * given @p error.
 *
 * @param session The active session where the offending request
 *                was received.
 * @param error   The error to send
 * @param response  A result parameter providing a pre-initialized
 *                  response.
 *
 * @return DCAF_OK on success, an error code otherwise.
 */
dcaf_result_t dcaf_set_error_response(const coap_session_t *session,
                                      dcaf_result_t error,
                                      coap_pdu_t *response);

void dcaf_parse_dcaf_key(dcaf_key_t *key, const cn_cbor* cose_key);


struct dcaf_ticket_t;
typedef struct dcaf_ticket_t dcaf_ticket_t;

/**
 * Parses the @p request as ticket request message into @p result.
 * This function returns DCAF_OK if the request was successfully
 * parsed and @p result has been updated. Otherwise, an error
 * code is returned.
 *
 * @param session  The session where the @p request was received.
 * @param request  The ticket request message.
 * @param result   A result parameter that will be filled in with a
 *                 pointer to a newly created dcaf_ticket_t  structure
 *                 with the authorization results in case the request
 *                 was successfully parsed. If and only if this
 *                 function returns DCAF_OK, @p *result will point
 *                 to a new dcaf_ticket_t object that must be released
 *                 by dcaf_delete_ticket().
 *
 * @return DCAF_OK on success, or an error code otherwise. The error
 *         code can be used to construct an error response by
 *         dcaf_set_error_response().
 */
dcaf_result_t dcaf_parse_ticket_request(const coap_session_t *session,
                                        const coap_pdu_t *request,
                                        dcaf_ticket_t **result);


void dcaf_set_ticket_grant(const coap_session_t *session,
                           const dcaf_ticket_t *ticket,
                           coap_pdu_t *response);

struct dcaf_nonce_t;
typedef struct dcaf_nonce_t dcaf_nonce_t;

/**
 * Searches the stored nonces for @p nonce with the size @p size and
 * determines the offset from the information stored with the nonce.
 * 
 * @param nonce      The nonce for which the stored nonces are searched.
 * @param nonce_size The size of the nonce.
 *
 * @return The offset on success or an error code.
 */
int dcaf_determine_offset_with_nonce(const uint8_t *nonces,size_t nonce_size);

/**
 * Parses @p data of size @p data_len into the ticket @p result.
 *
 * @param session  The session where the @p request was received.
 * @param data     The raw CBOR data to parse.
 * @param data_len The lenght of @p data.
 * @param result   A result parameter that will be filled in with a
 *                 pointer to a newly created dcaf_ticket_t structure
 *                 If and only if this
 *                 function returns DCAF_OK, @p *result will point
 *                 to a new dcaf_ticket_t object that must be released
 *                 by dcaf_free_ticket().
 *
 * @return DCAF_OK on success, or an error code otherwise. The error
 *         code can be used to construct an error response by
 *         dcaf_set_error_response().
 */
dcaf_result_t dcaf_parse_ticket_face(const coap_session_t *session,
				const uint8_t *data, size_t data_len,
				dcaf_ticket_t **result);

typedef coap_time_t dcaf_time_t;

/**
 * Returns the current time.
 *
 * @return The current time.
 */
dcaf_time_t dcaf_gettime(void);

struct dcaf_dep_ticket_t;
typedef struct dcaf_dep_ticket_t dcaf_dep_ticket_t;

dcaf_nonce_t *dcaf_new_nonce(size_t len);

dcaf_dep_ticket_t *dcaf_new_dep_ticket(const unsigned long seq,
				       const dcaf_time_t ts,
				       const uint remaining_time);

dcaf_ticket_t *dcaf_new_ticket(const dcaf_key_type key_type,
                               const unsigned long seq, const dcaf_time_t ts,
			       const uint remaining_time);


void dcaf_add_ticket(dcaf_ticket_t *ticket);

/**
 * Releases the storage that has been allocated for @p ticket
 * by dcaf_new_ticket().
 *
 * @param ticket The DCAF ticket to release.
 */
void dcaf_free_ticket(dcaf_ticket_t *ticket);

/**
 *  Removes @p ticket from the list of tickets.
 * 
 * @param ticket The DCAF ticket to remove.
 */
void dcaf_remove_ticket(dcaf_ticket_t *ticket);

/**
 * Creates a ticket verifier from authorization information given in
 * @p ticket.  On success, this function will set ticket->key to a
 * proper verifier.
 *
 * @param ctx    The current DCAF context.
 * @param ticket  The authorization information object with which
 *               the verifier should be used.
 *
 * @return DCAF_OK on success, an error code otherwise.
 */
dcaf_result_t dcaf_create_verifier(dcaf_context_t *ctx,
                                   dcaf_ticket_t *ticket);

#ifdef __cplusplus
}
#endif

#endif /* _DCAF_H_ */
