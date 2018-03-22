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

#include <coap/coap.h>

#ifdef __cplusplus
extern "C" {
#ifdef EMACS_NEEDS_A_CLOSING_BRACKET
}
#endif
#endif

#define DCAF_TOKEN_DEFAULT "token"

/** Default lifetime of a DCAF access ticket in seconds. */
#define DCAF_DEFAULT_LIFETIME       3600

typedef enum {
  DCAF_OK,
  DCAF_ERROR_OUT_OF_MEMORY,
  DCAF_ERROR_BUFFER_TOO_SMALL,
  DCAF_ERROR_INTERNAL_ERROR,
  DCAF_ERROR_BAD_REQUEST          = 0x10,
  DCAF_ERROR_UNAUTHORIZED         = 0x13,
  DCAF_ERROR_INVALID_AIF          = 0x15,
  DCAF_ERROR_UNSUPPORTED_KEY_TYPE = 0x16
} dcaf_result_t;

#include "dcaf_address.h"
#include "dcaf_debug.h"
#include "dcaf_crypto.h"
#include "dcaf_key.h"
#include "dcaf_optlist.h"
#include "dcaf_prng.h"

#include "cose.h"

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

struct dcaf_authz_t;
typedef struct dcaf_authz_t dcaf_authz_t;

/**
 * Creates a new DCAF context with the configuration given in @p
 * config. If @p config is NULL or config options are set to NULL
 * values, proper defaults will be used.
 *
 * @param config       Configuration options or NULL for defaults.
 */
dcaf_context_t *dcaf_new_context(const dcaf_config_t *config);

void dcaf_free_context(dcaf_context_t *context);

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

/**
 * Parses the @p request as ticket request message into @p result.
 * This function returns DCAF_OK if the request was successfully
 * parsed and @p result has been updated. Otherwise, an error
 * code is returned.
 *
 * @param session  The session where the @p request was received.
 * @param request  The ticket request message.
 * @param result   A result parameter that will be filled in with a
 *                 pointer to a newly created dcaf_authz_t  structure
 *                 with the authorization results in case the request
 *                 was successfully parsed. If and only if this
 *                 function returns DCAF_OK, @p *result will point
 *                 to a new dcaf_authz_t object that must be released
 *                 by dcaf_delete_authz().
 *
 * @return DCAF_OK on success, or an error code otherwise. The error
 *         code can be used to construct an error response by
 *         dcaf_set_error_response().
 */
dcaf_result_t dcaf_parse_ticket_request(const coap_session_t *session,
                                        const coap_pdu_t *request,
                                        dcaf_authz_t **result);

/**
 * Releases the memory that was allocated for @p authz.
 *
 * @param authz The dcaf_authz_t object to delete.
 */
void dcaf_delete_authz(dcaf_authz_t *authz);

void dcaf_set_ticket_grant(const coap_session_t *session,
                           const dcaf_authz_t *authz,
                           coap_pdu_t *response);

struct dcaf_ticket_t;
typedef struct dcaf_ticket_t dcaf_ticket_t;

dcaf_ticket_t *dcaf_new_ticket(const uint8_t *kid, size_t kid_length,
                               const uint8_t *verifier, size_t verifier_length);
void dcaf_add_ticket(dcaf_ticket_t *ticket);

/**
 * Creates a ticket verifier from authorization information given in
 * @p authz.  On success, this function will set authz->key to a
 * proper verifier.
 *
 * @param ctx    The current DCAF context.
 * @param authz  The authorization information object with which
 *               the verifier should be used.
 *
 * @return DCAF_OK on success, an error code otherwise.
 */
dcaf_result_t dcaf_create_verifier(dcaf_context_t *ctx,
                                   dcaf_authz_t *authz);

#ifdef __cplusplus
}
#endif

#endif /* _DCAF_H_ */
