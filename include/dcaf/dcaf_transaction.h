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

#include <coap/coap.h>
#include "dcaf.h"

struct dcaf_transaction_t;
typedef struct dcaf_transaction_t dcaf_transaction_t;

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
                                            int method,
                                            const char *uri,
                                            size_t uri_len,
                                            dcaf_optlist_t options,
                                            void *data,
                                            size_t data_len,
                                            int flags);

/** Releases the storage that was allocated for @p transaction. */
void dcaf_delete_transaction(dcaf_context_t *dcaf_context,
                             dcaf_transaction_t *transaction);

void dcaf_transaction_set_reponse_handler(dcaf_transaction_t *transaction,
                                          dcaf_response_handler_t rhnd);

void dcaf_transaction_set_error_handler(dcaf_transaction_t *transaction,
                                        dcaf_error_handler_t ehnd);

dcaf_transaction_t *dcaf_find_transaction(dcaf_context_t *dcaf_context,
                                          const coap_address_t *peer,
                                          const coap_pdu_t *pdu);

dcaf_transaction_result_t dcaf_transaction_start(dcaf_context_t *dcaf_context,
                                              dcaf_transaction_t *transaction);

#endif /* _DCAF_TRANSACTION_H_ */
