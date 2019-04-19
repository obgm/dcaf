/*
 * dcaf_am.h -- AM-specific functionality
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 *
 * Extended by Sara Stadler 2018/2019
 */

#ifndef _DCAF_AM_H_
#define _DCAF_AM_H_ 1

#ifdef __cplusplus
extern "C" {
#ifdef EMACS_NEEDS_A_CLOSING_BRACKET
}
#endif
#endif

#include "dcaf_abc.h"

struct dcaf_ticket_request_t;
typedef struct dcaf_ticket_request_t dcaf_ticket_request_t;




struct dcaf_attribute_request_t;
typedef struct dcaf_attribute_request_t dcaf_attribute_request_t;

/**
 * Deletes the @p ticket_request that was created by
 * dcaf_parse_ticket_request() and releases its allocated resources.
 *
 * @param ticket_request The dcaf_ticket_request_t structure to
 *                       release.
 */
void dcaf_delete_ticket_request(dcaf_ticket_request_t *ticket_request);

void
dcaf_delete_attribute_request(dcaf_attribute_request_t *areq);


/**
 * Parses the @p request as ticket request message into @p result.
 * This function returns DCAF_OK if the request was successfully
 * parsed and @p result has been updated. Otherwise, an error
 * code is returned.
 *
 * @param request  The ticket request message.
 * @param result A result parameter that will be filled in with a
 *                 pointer to a newly created dcaf_ticket_request_t
 *                 structure with the authorization results in case
 *                 the request was successfully parsed. If and only if
 *                 this function returns DCAF_OK, @p *result will
 *                 point to a new dcaf_ticket_request_t object that
 *                 must be released by dcaf_delete_ticket_request().
 *
 * @return DCAF_OK on success, or an error code otherwise. The error
 *         code can be used to construct an error response by
 *         dcaf_set_error_response().
 */
dcaf_result_t dcaf_parse_ticket_request(
                                        const coap_pdu_t *request,
                                        dcaf_ticket_request_t **result);



/**
 * Parses the @p request as attribute info message into @p result.
 * This function returns DCAF_OK if the request was successfully
 * parsed and @p result has been updated. Otherwise, an error
 * code is returned.
 *
 * @param request  The attribute info message.
 * @param result A result parameter that will be filled in with a
 *                 pointer to a newly created dcaf_attribute_request_t
 *                 structure in case
 *                 the request was successfully parsed. If and only if
 *                 this function returns DCAF_OK, @p *result will
 *                 point to a new dcaf_attribute_request_t object that
 *                 must be released by dcaf_delete_attribute_request().
 *@param credential_descriptions The credential_list_st needed to verify
 *					correctness of the attribute info message.
 *
 * @return DCAF_OK on success, or an error code otherwise. The error
 *         code can be used to construct an error response by
 *         dcaf_set_error_response().
 */
dcaf_result_t
dcaf_parse_attribute_info(
                          const coap_pdu_t *request,
                          dcaf_attribute_request_t **result,
						  credential_list_st *cred_descriptios);

/**
 * Parses The proof string in  a disclosure proof message into @p result.
 * This function returns DCAF_OK if the proof was successfully
 * parsed and @p result has been updated. Otherwise, an error
 * code is returned.
 *
 * @param proof    The disclosure proof message.
 * @param result   A result parameter that will be filled in with a
 *                 pointer to a newly created string in case
 *                 the request was successfully parsed. If and only if
 *                 this function returns DCAF_OK, @p *result will
 *                 point to a new string object that
 *                 must be released by dcaf_delete_string().
 *
 * @return DCAF_OK on success, or an error code otherwise. The error
 *         code can be used to construct an error response by
 *         dcaf_set_error_response().
 */
dcaf_result_t
dcaf_parse_disclosure_proof(const coap_pdu_t *proof,
                          str_st **result);


/**
 * Generates a ticket_request message from the given @p ticket_request.
 * Also sets media_type, max_age and uri_path option.
 * @return DCAF_OK if the payload is set to a valid ticket_request message
 * 			and DCAF_ERROR_INTERNAL_ERROR otherwise
 * @param payload The message to fill
 * @param ticket_request The ticket request to be written into the payload
 * */
dcaf_result_t
dcaf_set_ticket_request(coap_pdu_t *payload, dcaf_ticket_request_t **ticket_request);

/**
 * Generates an attribute info message using the given credential id and attribute flag.
 * Also sets media_type, max_age and uri_path option.
 * @return DCAF_OK if the payload is set to a valid attribute_info message
 * 			and DCAF_ERROR_INTERNAL_ERROR if the payload is set to an error
 * 			 message (code 500).
 * 	@param response The message to fill
 * 	@param cred_id The credential id to be written into the response payload
 * 	@param attr The attribute flag to be written into the response payload
 * 	@param n The nonce to be written into the response payload
 * 	*/
dcaf_result_t
dcaf_set_attribute_info(coap_pdu_t *response, uint64_t cred_id, uint attr, dcaf_nonce_t *n);


/**
 * Computes a disclosure proof according to the given request using the
 * given credential and issuers public key. From the proof a disclosure proof
 * message is generated and written into the payload.
 * Also sets media_type, max_age and uri_path option.
 * @return DCAF_OK if the payload is set to a valid disclosure proof message
 * 			and DCAF_ERROR_INTERNAL_ERROR otherwise
 * @param attributes the attributes to be disclosed in the proof
 * @param transformed_nonce the nonce to be used for the disclosure proof
 * @param response The message to fill
 * @param credential_file The path to the credential to be used for the selective disclosure
 * @param public_key_file The path to the file containing the credential issuer's public key
 * */
dcaf_result_t
dcaf_set_disclosure_proof(
                      int attributes, dcaf_nonce_t *transformed_nonce,
                      coap_pdu_t *response, const char *credential_file, const char *public_key_file);

/**
 * Writes a ticket grant according to @p ticket_request into
 * @p *response. If the request was denied, an error response will
 * be written and DCAF_ERROR_INTERNAL_ERROR will be returned. Otherwise
 * DCAF_OK will be returned.
 *
 * @param session        The session where the ticket was received.
 * @param ticket_request The parsed ticket request as created by
 *                       dcaf_parse_ticket_request().
 * @param response       The response message to fill.
 */
dcaf_result_t dcaf_set_ticket_grant(const coap_session_t *session,
                           const dcaf_ticket_request_t *ticket_request,
                           coap_pdu_t *response);
#ifdef __cplusplus
}
#endif

#endif /* _DCAF_AM_H_ */
