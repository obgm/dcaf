/*
 * dcaf_transaction.h -- DCAF transaction store
 *
 * Copyright (C) 2015-2016 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2016 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_TRANSACTION_H_
#define _DCAF_TRANSACTION_H_ 1

#include "dcaf.h"

struct dcaf_transaction_t;
typedef struct dcaf_transaction_t dcaf_transaction_t;

struct coap_address_t;
struct coap_pdu_t;

typedef enum {
  DCAF_TRANSACTION_OK,
  DCAF_TRANSACTION_ERROR,
  DCAF_TRANSACTION_NOT_SENT
} dcaf_transaction_result_t;

typedef dcaf_transaction_result_t (*dcaf_response_handler_t)
                                       (dcaf_context_t *,
                                        dcaf_transaction_t *,
                                        coap_pdu_t *);

typedef void (*dcaf_error_handler_t)(dcaf_context_t *,
                                     dcaf_transaction_t *,
                                     int error);

/**
 * Creates a new transaction object. When finished, the storage
 * allocated for this object must be released with
 * dcaf_transaction_free().
 *
 * @return The created transaction object or NULL on error.
*/
dcaf_transaction_t *dcaf_create_transaction(dcaf_context_t *dcaf_context,
                                            coap_session_t *session,
                                            coap_pdu_t *pdu);

/** Releases the storage that was allocated for @p transaction. */
void dcaf_delete_transaction(dcaf_context_t *dcaf_context,
                             dcaf_transaction_t *transaction);

void dcaf_transaction_set_reponse_handler(dcaf_transaction_t *transaction,
                                          dcaf_response_handler_t rhnd);

void dcaf_transaction_set_error_handler(dcaf_transaction_t *transaction,
                                        dcaf_error_handler_t ehnd);

dcaf_transaction_t *dcaf_find_transaction(dcaf_context_t *dcaf_context,
                                          const coap_session_t *session,
                                          const coap_pdu_t *pdu);

dcaf_transaction_result_t dcaf_transaction_start(dcaf_context_t *dcaf_context,
                                              dcaf_transaction_t *transaction);

/**
 * Sends a request with method @p code to the endpoint denoted
 * by @p uri_str. The options specified in @p options and the
 * payload given as @p data are added to the newly created
 * CoAP message. This function returns DCAF_OK if the request
 * could be created and was passed to the DCAF transaction
 * layer. Otherwise, an error code is returned.
 *
 * @param dcaf_context  The DCAF context to use.
 * @param code          The CoAP method to use.
 * @param uri_str       The destination URI.
 * @param uri_len       The actual length of @p uri_str.
 * @param options       An optional list of CoAP options
 *                      to add to the request. This argument
 *                      may be NULL.
 * @param data          The message's payload. This argument
 *                      may be NULL.
 * @param data_len      The actual length of @p data. Must
 *                      be 0 if @p data is NULL.
 * @param flags         Optional flags. Should be set to 0
 *                      for now.
 *
 * @return DCAF_OK on success, an error code otherwise.
 */
dcaf_result_t dcaf_send_request(dcaf_context_t *dcaf_context,
                                int code,
                                const char *uri_str,
                                size_t uri_len,
                                dcaf_optlist_t options,
                                const uint8_t *data,
                                size_t data_len,
                                int flags);

#endif /* _DCAF_TRANSACTION_H_ */
