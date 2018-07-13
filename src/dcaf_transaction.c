/*
 * dcaf_transaction.c -- DCAF transaction store
 *
 * Copyright (C) 2015-2016 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2016 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include "dcaf/dcaf_transaction.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/utlist.h"

#define DCAF_MAX_TOKEN 8

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif /* min */

static unsigned short
get_default_port(const coap_uri_t *u) {
  return coap_uri_scheme_is_secure(u) ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT;
}

static int
set_uri_options(coap_uri_t *uri, dcaf_optlist_t *optlist) {
#define BUFSIZE 40
  unsigned char _buf[BUFSIZE];
  unsigned char *buf = _buf;
  size_t buflen;
  int result;

  dcaf_optlist_remove_key(optlist, COAP_OPTION_URI_HOST);
  dcaf_optlist_remove_key(optlist, COAP_OPTION_URI_PORT);
  dcaf_optlist_remove_key(optlist, COAP_OPTION_URI_PATH);
  dcaf_optlist_remove_key(optlist, COAP_OPTION_URI_QUERY);

  if (uri->port != get_default_port(uri)) {
    unsigned char portbuf[2];

    dcaf_optlist_insert(optlist,
                dcaf_option_create(COAP_OPTION_URI_PORT,
                                   portbuf,
                                   coap_encode_var_safe(portbuf,
                                                        sizeof(portbuf),
                                                        uri->port)));
  }

  if (uri->path.length) {
    buflen = BUFSIZE;
    result = coap_split_path(uri->path.s, uri->path.length, buf, &buflen);

    while (result--) {
      dcaf_optlist_insert(optlist,
                          dcaf_option_create(COAP_OPTION_URI_PATH,
                                             coap_opt_value(buf),
                                             coap_opt_length(buf)));

      buf += coap_opt_size(buf);
    }
  }

  if (uri->query.length) {
    buflen = BUFSIZE;
    buf = _buf;
    result = coap_split_query(uri->query.s, uri->query.length, buf, &buflen);

    while (result--) {
      dcaf_optlist_insert(optlist,
                          dcaf_option_create(COAP_OPTION_URI_QUERY,
                                             coap_opt_value(buf),
                                             coap_opt_length(buf)));

      buf += coap_opt_size(buf);
    }
  }

  return 0;  
}

dcaf_transaction_t *
dcaf_create_transaction(dcaf_context_t *dcaf_context,
                        int code,
                        const char *uri_str,
                        size_t uri_len,
                        dcaf_optlist_t options,
                        void *data,
                        size_t data_len,
                        int flags) {
#if 0
  dcaf_transaction_t *transaction;
  coap_uri_t uri;
  int result;
  transaction = coap_malloc(sizeof(dcaf_transaction_t));
  
  if (!transaction) {
    coap_log(LOG_WARNING, "cannot allocate DCAF transaction\n");
    return NULL;
  }

  memset(transaction, 0, sizeof(dcaf_transaction_t));
  transaction->tid = COAP_INVALID_TID;

  transaction->pdu =
    coap_pdu_init(flags & 0x07, code, 0, COAP_DEFAULT_PDU_SIZE);

  /* FIXME: generate random token */
  if (!coap_add_token(transaction->pdu, 4, (unsigned char *)"1234")) {
    debug("cannot add token to request\n");
  }

  if (coap_split_uri((unsigned char *)uri_str, uri_len, &uri) < 0) {
    debug("cannot process URI\n");
    return NULL;
  }

  /* set remote address from uri->host */
  result = dcaf_set_coap_address(uri.host.s,
                                 uri.host.length,
                                 uri.port,
                                 &transaction->remote);
  if (result < 0) {
    debug("cannot resolve URI host '%.*s'\n", uri.host.length, uri.host.s);
    return NULL;
  }
  
  /* Select endpoint according to URI scheme and remote address. */
  transaction->local_interface =
    dcaf_select_interface(dcaf_context, &transaction->remote,
                          coap_uri_scheme_is_secure(&uri));
  if (!transaction->local_interface) {
    coap_log(LOG_EMERG, "cannot find endpoint for transaction\n");
    return NULL;
  }

  result = set_uri_options(&uri, &options);

  if (options && (dcaf_optlist_serialize(options, transaction->pdu) < 0)) {
    warn("cannot set CoAP options\n");
  }

  if (data && data_len) {
      size_t available = transaction->pdu->max_size - transaction->pdu->length;

      /* add block if data is too large or if block.num > 0 */
      if ((data_len < available) && (transaction->block.num == 0)) {
        coap_add_data(transaction->pdu, data_len, data);
      } else {
        if (transaction->block.num == 0) {
          /* calculate block size wrt available space */
          transaction->block.szx = min(COAP_MAX_BLOCK_SZX,
                                       coap_fls(available >> 4));
        }

        coap_add_block(transaction->pdu, data_len, data,
                       transaction->block.num, transaction->block.szx);
      }
  }

  return transaction;
#endif
  return NULL;
}

void
dcaf_delete_transaction(dcaf_context_t *dcaf_context,
                        dcaf_transaction_t *transaction) {
  if (transaction) {
    LL_DELETE(dcaf_context->transactions, transaction);
    coap_delete_pdu(transaction->pdu);
    coap_free(transaction);
  }
}

void
dcaf_transaction_set_reponse_handler(dcaf_transaction_t *transaction,
                                     dcaf_response_handler_t rhnd) {
  transaction->response_handler = rhnd;
}

void
dcaf_transaction_set_error_handler(dcaf_transaction_t *transaction,
                                   dcaf_error_handler_t ehnd) {
  transaction->error_handler = ehnd;
}

dcaf_transaction_t *
dcaf_find_transaction(dcaf_context_t *dcaf_context,
                      const coap_address_t *peer,
                      const coap_pdu_t *pdu) {
#if 0
  coap_tid_t id;
  dcaf_transaction_t *transaction;

  coap_transaction_id(peer, pdu, &id);

  LL_SEARCH_SCALAR(dcaf_context->transactions, transaction, tid, id);
  if (!transaction) {
    coap_log(LOG_DEBUG, "transaction not found\n");
    return NULL;
  }

  coap_log(LOG_DEBUG, "found transaction %d\n", id);
  return transaction;
#endif
  return NULL;
}

dcaf_transaction_result_t
dcaf_transaction_start(dcaf_context_t *dcaf_context,
                       dcaf_transaction_t *transaction) {
  coap_context_t *coap_context = dcaf_context->coap_context;
#if 0
  LL_PREPEND(dcaf_context->transactions, transaction);

  if (transaction->pdu == NULL) {
    debug("transaction object has no associated PDU\n");
    return DCAF_TRANSACTION_ERROR;
  }

  transaction->pdu->hdr->id = coap_new_message_id(coap_context);
  if (transaction->pdu->hdr->type == COAP_MESSAGE_CON) {
    transaction->tid = coap_send_confirmed(coap_context,
                                           transaction->local_interface,
                                           &transaction->remote,
                                           transaction->pdu);
  } else {
    transaction->tid = coap_send(coap_context,
                                 coap_context->endpoint,
                                 &transaction->remote,
                                 transaction->pdu);
  }

  /* When libcoap has accepted the PDU we have to clear our pointer to
   * avoid double free. */
  if (transaction->tid != COAP_INVALID_TID) {
    transaction->pdu = NULL;
    return DCAF_TRANSACTION_OK;
  } else {
    LL_DELETE(dcaf_context->transactions, transaction);
    return DCAF_TRANSACTION_NOT_SENT;
  }
#endif
}

#undef min
