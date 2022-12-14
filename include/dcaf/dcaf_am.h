/*
 * dcaf_am.h -- AM-specific functionality
 *
 * Copyright (C) 2018-2021 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_AM_H_
#define _DCAF_AM_H_ 1

#ifdef __cplusplus
extern "C" {
#ifdef EMACS_NEEDS_A_CLOSING_BRACKET
}
#endif
#endif

#include "dcaf/dcaf.h"

/**
 * Parses the @p request as ticket request message into @p result.
 * This function returns DCAF_OK if the request was successfully
 * parsed and @p result has been updated. Otherwise, an error
 * code is returned.
 *
 * @param session  The session where the @p request was received.
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
dcaf_result_t dcaf_parse_ticket_request(const coap_session_t *session,
                                        const coap_pdu_t *request,
                                        dcaf_ticket_request_t **result);

/**
 * Writes a ticket grant according to @p ticket_request into
 * @p *response. If the request was denied, an error response will
 * be written.
 *
 * @param session        The session where the ticket request was
 *                       received.
 * @param ticket_request The parsed ticket request as created by
 *                       dcaf_parse_ticket_request().
 * @param response       The response message to fill.
 *
 * @return               Returns a new dcaf_ticket_t object if a
 *                       ticket was created or @c NULL on error.
 *                       As tickets may be released automatically
 *                       when expired, care must be taken to access
 *                       ticket contents only if dcaf_check_ticket()
 *                       is successful.
 */
const dcaf_ticket_t *dcaf_set_ticket_grant(const coap_session_t *session,
                           const dcaf_ticket_request_t *ticket_request,
                           coap_pdu_t *response);

/**
 * Deletes the @p ticket_request that was created by
 * dcaf_parse_ticket_request() and releases its allocated resources.
 *
 * @param ticket_request The dcaf_ticket_request_t structure to
 *                       release.
 */
void dcaf_delete_ticket_request(dcaf_ticket_request_t *ticket_request);

bool dcaf_get_audience(const dcaf_ticket_request_t *ticket_request,
                       const char **audience);


#ifdef __cplusplus
}
#endif

#endif /* _DCAF_AM_H_ */
