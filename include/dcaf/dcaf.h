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

typedef enum {
  DCAF_OK,
  DCAF_ERROR_BUFFER_TOO_SMALL,
  DCAF_ERROR_BAD_REQUEST,
  DCAF_ERROR_INTERNAL_ERROR
} dcaf_result_t;

#include "dcaf_address.h"
#include "dcaf_crypto.h"
#include "dcaf_optlist.h"
#include "dcaf_prng.h"

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

dcaf_authz_t *dcaf_parse_authz_request(const coap_session_t *session,
                                       const coap_pdu_t *request);

void dcaf_set_ticket_grant(const coap_session_t *session,
                           const dcaf_authz_t *authz,
                           coap_pdu_t *response);

/**
 * Creates a ticket verifier from @p face of length @p face_length
 * using the key material from @p key and the algorithm @p alg. The
 * result is placed into @p output. @p out_length is a pointer to a
 * variable that is initialized with the maximum number of bytes
 * available in @p output. On success, the number of bytes actually
 * written is stored in @p *out_length. This function returns DCAF_OK
 * on success, an error value otherwise.
 *
 * @param params The key material and algorithm to use.
 * @param face   The ticket face for which the verifier should be
 *               generated.
 * @param face_length The length of @p face in bytes.
 * @param output A buffer for storing the result.
 * @param out_length A pointer to a size_t variable that specifies
 *               the number of bytes available in @p output. On success,
 *               the variable pointed to by @p out_length contains
 *               the number of bytes that have actually been written
 *               to @p output.
 * @return DCAF_OK on success, an error code otherwise.
 */
dcaf_result_t dcaf_create_verifier(const dcaf_crypto_param_t *params,
                                   const uint8_t *face,
                                   size_t face_length,
                                   uint8_t *output,
                                   size_t *out_length);

#ifdef __cplusplus
}
#endif

#endif /* _DCAF_H_ */
