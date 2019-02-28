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

/**
 * The maximum size of a URI path that dcaf_send_request() can
 * handle. As the URI is split on the stack, it should be reasonably
 * sized for constrained devices. */
#ifndef MAX_URI_PATH_SIZE
#define MAX_URI_PATH_SIZE 64
#endif /* MAX_URI_PATH_SIZE */

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
 * dcaf_transaction_free(). The newly created transaction object
 * stores a copy of the given @p pdu for later use.
 *
 * @return The created transaction object or NULL on error.
*/
dcaf_transaction_t *dcaf_create_transaction(dcaf_context_t *dcaf_context,
                                            coap_session_t *session,
                                            const coap_pdu_t *pdu);

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

/** Checks if @p transaction is valid. */
int dcaf_check_transaction(dcaf_context_t *dcaf_context,
                           const dcaf_transaction_t *transaction);

/** Updates the @p transaction according to @p session and @p pdu. */
void dcaf_transaction_update(dcaf_transaction_t *transaction,
                             const coap_session_t *session,
                             const coap_pdu_t *pdu);

dcaf_transaction_result_t dcaf_transaction_start(dcaf_context_t *dcaf_context,
                                              dcaf_transaction_t *transaction);

coap_pdu_t *
copy_pdu(coap_pdu_t *dst, const coap_pdu_t *src);

/** @defgroup transaction_flags Flags for transaction control
 *
 *  @{
 */

/**
 * Return immediately after initiating a transaction.

 * This flag tells transaction-initiating functions such as
 * dcaf_send_request() and dcaf_send_request_uri() to return
 * immediately without waiting for a response.  This flag must not be
 * combined with DCAF_TRANSACTION_BLOCK.
 */
#define DCAF_TRANSACTION_NONBLOCK  0x00

/**
 * Wait until transaction has finished.
 *
 * Signals transaction-initiating functions such as
 * dcaf_send_request() and dcaf_send_request_uri() to return only
 * after the transaction has finished. This flag must not be
 * combined with DCAF_TRANSACTION_NONBLOCK.
 */
#define DCAF_TRANSACTION_BLOCK     0x01

/**@}*/

/**
 * Sends a request with method @p code to the endpoint denoted by @p
 * uri. The options specified in @p options and the payload given as
 * @p data are added to the newly created CoAP message. This function
 * returns a pointer to a newly created dcaf_transaction_t structure
 * if the request could be created and was passed to the DCAF
 * transaction layer. Otherwise, NULL is returned. The transaction
 * object needs to be freed via dcaf_delete_transaction().
 *
 * @param dcaf_context  The DCAF context to use.
 * @param code          The CoAP method to use.
 * @param uri_str       The destination URI.
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
 * @return A new transaction structure on success, or NULL otherwise.
 */
dcaf_transaction_t *dcaf_send_request_uri(dcaf_context_t *dcaf_context,
                                          int code,
                                          const coap_uri_t *uri,
                                          dcaf_optlist_t options,
                                          const uint8_t *data,
                                          size_t data_len,
                                          int flags);
/**
 * Sends a request with method @p code to the endpoint denoted
 * by @p uri_str. The options specified in @p options and the
 * payload given as @p data are added to the newly created
 * CoAP message.  This function returns a pointer to a newly
 * created dcaf_transaction_t structure if the request could be
 * created and was passed to the DCAF transaction layer. Otherwise,
 * NULL is returned. The transaction object needs to be freed via
 * dcaf_delete_transaction().
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
 * @return A new transaction structure on success, or NULL otherwise.
 */
dcaf_transaction_t *dcaf_send_request(dcaf_context_t *dcaf_context,
                                      int code,
                                      const char *uri_str,
                                      size_t uri_len,
                                      dcaf_optlist_t options,
                                      const uint8_t *data,
                                      size_t data_len,
                                      int flags);

#endif /* _DCAF_TRANSACTION_H_ */
