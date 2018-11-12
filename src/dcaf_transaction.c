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

#if 0
static unsigned short
get_default_port(const coap_uri_t *u) {
  return coap_uri_scheme_is_secure(u) ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT;
}
#endif

static int
set_uri_options(coap_uri_t *uri, dcaf_optlist_t *optlist) {
  unsigned char buf[MAX_URI_PATH_SIZE];
  unsigned char *bufp = buf;
  size_t buf_size = sizeof(buf);
  int num_segments =
    coap_split_path(uri->path.s, uri->path.length, buf, &buf_size);

  /* TODO: remove options to replace from optlist */
  for (int i = 0; (i < num_segments) && (buf_size > 0); i++) {
    coap_option_t opt;
    size_t len = coap_opt_parse(bufp, buf_size, &opt);
    if (!len) {
      dcaf_log(DCAF_LOG_WARNING, "invalid URI encountered\n");
      return -1;
    } else {
      coap_insert_optlist(optlist,
                          coap_new_optlist(COAP_OPTION_URI_PATH,
                                           opt.length, opt.value));
      bufp += len;
      buf_size -= len;
    }
  }

  return 0;
}

static size_t
get_token_from_pdu(const coap_pdu_t *pdu, void *buf, size_t max_buf) {
  const uint8_t *token;
  size_t token_length;

  assert(pdu);
  assert(buf);

  token_length = coap_get_token_length(pdu);
  if (token_length && (token = coap_get_token(pdu))) {
    size_t written = min(token_length, max_buf);
    memcpy(buf, token, written);
    return written;
  }
  return 0;
}

dcaf_transaction_t *
dcaf_create_transaction(dcaf_context_t *dcaf_context,
                        coap_session_t *session,
                        coap_pdu_t *pdu) {
  dcaf_transaction_t *transaction;
  assert(dcaf_context);
  assert(session);
  assert(pdu);

  transaction = (dcaf_transaction_t *)dcaf_alloc_type(DCAF_TRANSACTION);
  if (!transaction) {
    dcaf_log(DCAF_LOG_WARNING, "cannot allocate DCAF transaction\n");
    return NULL;
  }

  memset(transaction, 0, sizeof(dcaf_transaction_t));
  get_token_from_pdu(pdu, &transaction->tid, sizeof(transaction->tid));
  transaction->pdu = pdu;

  transaction->state = DCAF_STATE_IDLE;
#if 0
  /* Select endpoint according to URI scheme and remote address. */
  transaction->local_interface =
    dcaf_select_interface(dcaf_context, &transaction->remote,
                          coap_uri_scheme_is_secure(&uri));
  if (!transaction->local_interface) {
    coap_log(LOG_EMERG, "cannot find endpoint for transaction\n");
    goto error;
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
#endif

  LL_PREPEND(dcaf_context->transactions, transaction);
  return transaction;
 error:
  dcaf_free_type(DCAF_TRANSACTION, transaction);
  coap_free(pdu);
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
                      const coap_session_t *session,
                      const coap_pdu_t *pdu) {
  coap_tid_t id;
  dcaf_transaction_t *transaction;
  (void)session;

  get_token_from_pdu(pdu, &id, sizeof(id));

  LL_SEARCH_SCALAR(dcaf_context->transactions, transaction, tid, id);
  if (!transaction) {
    dcaf_log(DCAF_LOG_DEBUG, "transaction not found\n");
    return NULL;
  }

  dcaf_log(DCAF_LOG_DEBUG, "found transaction %d\n", id);
  return transaction;
}

dcaf_transaction_result_t
dcaf_transaction_start(dcaf_context_t *dcaf_context,
                       dcaf_transaction_t *transaction) {
#if 1
  (void)dcaf_context;
  (void)transaction;
  return DCAF_TRANSACTION_NOT_SENT;
#else
  coap_context_t *coap_context = dcaf_context->coap_context;
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

dcaf_result_t
dcaf_send_request(dcaf_context_t *dcaf_context,
                  int code,
                  const char *uri_str,
                  size_t uri_len,
                  dcaf_optlist_t options,
                  const uint8_t *data,
                  size_t data_len,
                  int flags) {
  coap_context_t *ctx;
  coap_uri_t uri;
  int result;
  dcaf_result_t res = DCAF_ERROR_BAD_REQUEST;
  coap_address_t dst;
  coap_pdu_t *pdu;
  coap_session_t *session;
  uint8_t token[DCAF_DEFAULT_TOKEN_SIZE];
  (void)flags;

  assert(dcaf_context);

  ctx = dcaf_get_coap_context(dcaf_context);
  assert(ctx);

  if (coap_split_uri((unsigned char *)uri_str, uri_len, &uri) < 0) {
    dcaf_log(DCAF_LOG_ERR, "cannot process request URI\n");
    return DCAF_ERROR_BAD_REQUEST;
  }

    /* set remote address from uri->host */
  result = dcaf_set_coap_address(uri.host.s, uri.host.length,
                                 uri.port, &dst);
  if (result < 0) {
    dcaf_log(DCAF_LOG_ERR, "cannot resolve URI host '%.*s'\n",
             (int)uri.host.length, uri.host.s);
    return DCAF_ERROR_BAD_REQUEST;
  }

  /* check if we have an ongoing session with this peer */
  if (!(session = coap_session_get_by_peer(ctx, &dst, 0 /* ifindex */))) {
    /* no session available, create new */
    if (coap_uri_scheme_is_secure(&uri)) {
      dcaf_key_t *k = dcaf_find_key(dcaf_context, uri.host.s, uri.host.length, NULL, 0);
      char identity[DCAF_MAX_KID_SIZE+1];

      if (!k) {
        dcaf_log(DCAF_LOG_ERR, "cannot find credentials for %.*s\n",
                 (int)uri.host.length, uri.host.s);
        return DCAF_ERROR_BAD_REQUEST;
      }
      if (k->kid_length > 0) {
        assert(sizeof(k->kid) < sizeof(identity));
        memcpy(identity, k->kid, k->kid_length);
      }
      identity[k->kid_length] = '\0';

      session = coap_new_client_session_psk(ctx, NULL, &dst,
                                            COAP_PROTO_DTLS,
                                            identity, k->data, k->length);
    } else { /* URI scheme for non-secure traffic */
      session = coap_new_client_session(ctx, NULL, &dst, COAP_PROTO_UDP);
    }
  }
  if (!session) {
    dcaf_log(DCAF_LOG_ERR, "cannot create session\n");
    return DCAF_ERROR_INTERNAL_ERROR;
  }

  pdu = coap_new_pdu(session);
  if (!pdu) {
    dcaf_log(DCAF_LOG_WARNING, "cannot create new PDU\n");
    return DCAF_ERROR_OUT_OF_MEMORY;
  }

  pdu->type = COAP_MESSAGE_CON;
  pdu->tid = coap_new_message_id(session);
  pdu->code = code;

  /* generate random token */
  if (!dcaf_prng(token, sizeof(token))
      || !coap_add_token(pdu, sizeof(token), token)) {
    dcaf_log(DCAF_LOG_DEBUG, "cannot add token to request\n");
    goto error;
  }

  /* insert URI options for request */
  set_uri_options(&uri, &options);
  coap_add_optlist_pdu(pdu, (coap_optlist_t **)&options);

  if (data && data_len && !coap_add_data(pdu, data_len, data)) {
      dcaf_log(DCAF_LOG_WARNING, "cannot set payload\n");
  }

  if (!dcaf_create_transaction(dcaf_context, session, pdu)) {
    dcaf_log(DCAF_LOG_WARNING, "cannot create new transaction\n");
    res = DCAF_ERROR_OUT_OF_MEMORY;
    goto error;
  }

  coap_send(session, pdu);

  return DCAF_OK;
 error:
  coap_free(pdu);
  return res;
}

#undef min
