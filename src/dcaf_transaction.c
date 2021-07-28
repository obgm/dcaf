/*
 * dcaf_transaction.c -- DCAF transaction store
 *
 * Copyright (C) 2015-2021 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2021 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include "dcaf/dcaf_coap.h"
#include "dcaf/dcaf_transaction.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/utlist.h"

#define DCAF_MAX_TOKEN 8

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif /* min */

static int
set_uri_options(const coap_uri_t *uri, uint16_t type, dcaf_optlist_t *optlist) {
  unsigned char buf[MAX_URI_PATH_SIZE];
  unsigned char *bufp = buf;
  size_t buf_size = sizeof(buf);
  int num_segments;

  if (type == COAP_OPTION_URI_PATH) {
    num_segments = coap_split_path(uri->path.s, uri->path.length, buf, &buf_size);
  } else if (type == COAP_OPTION_URI_QUERY) {
    num_segments = coap_split_query(uri->query.s, uri->query.length, buf, &buf_size);
  } else { /* not supported */
    return -1;
  }

  /* TODO: remove options to replace from optlist */
  for (int i = 0; (i < num_segments) && (buf_size > 0); i++) {
    coap_option_t opt;
    size_t len = coap_opt_parse(bufp, buf_size, &opt);
    if (!len) {
      dcaf_log(DCAF_LOG_WARNING, "invalid URI-%s encountered\n",
               (type == COAP_OPTION_URI_PATH) ? "Path" : "Query");
      return -1;
    } else {
      coap_insert_optlist(optlist,
                          coap_new_optlist(type, opt.length, opt.value));
      bufp += len;
      buf_size -= len;
    }
  }

  return 0;
}

dcaf_transaction_t *
dcaf_create_transaction(dcaf_context_t *dcaf_context,
                        coap_session_t *session,
                        const coap_pdu_t *pdu) {
  dcaf_transaction_t *transaction;
  assert(dcaf_context);
  assert(session);

  transaction = (dcaf_transaction_t *)dcaf_alloc_type(DCAF_TRANSACTION);
  if (!transaction) {
    dcaf_log(DCAF_LOG_WARNING, "cannot allocate DCAF transaction\n");
    return NULL;
  }

  memset(transaction, 0, sizeof(dcaf_transaction_t));
  if (pdu) {
    coap_bin_const_t token;
    token = coap_pdu_get_token(pdu);
    memcpy(&transaction->tid, token.s,
           min(token.length, sizeof(transaction->tid)));
    transaction->pdu = coap_pdu_duplicate(pdu, session,
                                          token.length, token.s,
                                          NULL);
    if (!transaction->pdu) {
      dcaf_free_type(DCAF_TRANSACTION, transaction);
      dcaf_log(DCAF_LOG_ERR, "insufficient memory for DCAF transaction\n");
      return NULL;      
    }
  }

  transaction->state.act = DCAF_STATE_IDLE;

  LL_PREPEND(dcaf_context->transactions, transaction);
  return transaction;
}

void
dcaf_delete_transaction(dcaf_context_t *dcaf_context,
                        dcaf_transaction_t *transaction) {
  if (transaction) {
    LL_DELETE(dcaf_context->transactions, transaction);
    coap_delete_pdu(transaction->pdu);
    dcaf_free_type(DCAF_STRING, transaction->aud.s);
    dcaf_free_type(DCAF_TRANSACTION, transaction);
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

void
dcaf_transaction_update(dcaf_transaction_t *transaction,
                        coap_session_t *session,
                        const coap_pdu_t *pdu) {
  coap_bin_const_t token;
  dcaf_log(DCAF_LOG_DEBUG, "update transaction %02x%02x%02x%02x\n",
           transaction->tid[0], transaction->tid[1],
           transaction->tid[2], transaction->tid[3]);

  token = coap_pdu_get_token(pdu);
  memcpy(&transaction->tid, token.s,
         min(token.length, sizeof(transaction->tid)));
  dcaf_log(DCAF_LOG_DEBUG, "to %02x%02x%02x%02x\n",
           transaction->tid[0], transaction->tid[1],
           transaction->tid[2], transaction->tid[3]);
  coap_delete_pdu(transaction->pdu);
  transaction->pdu = coap_pdu_duplicate(pdu, session,
                                        token.length, token.s,
                                        NULL);
  if (!transaction->pdu) {
    dcaf_log(DCAF_LOG_WARNING, "insufficient memory for DCAF transaction update\n");
  }
}

dcaf_transaction_t *
dcaf_find_transaction(dcaf_context_t *dcaf_context,
                      const coap_session_t *session,
                      const coap_pdu_t *pdu) {
  dcaf_transaction_id_t id;
  dcaf_transaction_t *transaction;
  coap_bin_const_t token;
  (void)session;

  token = coap_pdu_get_token(pdu);
  memset(id, 0, sizeof(id));
  memcpy(id, token.s, min(sizeof(id), token.length));

  LL_FOREACH(dcaf_context->transactions, transaction) {
    if (memcmp(transaction->tid, id, sizeof(id)) == 0) {
      dcaf_log(DCAF_LOG_DEBUG, "found transaction %02x%02x%02x%02x\n",
               id[0], id[1], id[2], id[3]);
      return transaction;
    }
  }
  dcaf_log(DCAF_LOG_DEBUG, "transaction %02x%02x%02x%02x not found\n",
           id[0], id[1], id[2], id[3]);
  return NULL;
}

int
dcaf_check_transaction(dcaf_context_t *dcaf_context,
                       const dcaf_transaction_t *transaction) {
  dcaf_transaction_t *t;

  if (transaction) {
    LL_FOREACH(dcaf_context->transactions, t) {
      if (t == transaction) {
        return 1;
      }
    }
  }
  return 0;
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
  if (transaction->tid != COAP_INVALID_MID) {
    transaction->pdu = NULL;
    return DCAF_TRANSACTION_OK;
  } else {
    LL_DELETE(dcaf_context->transactions, transaction);
    return DCAF_TRANSACTION_NOT_SENT;
  }
#endif
}

void
dcaf_loop_io(dcaf_context_t *dcaf_context, dcaf_transaction_t *transaction) {
  coap_context_t *ctx;
  bool done = false;
  unsigned int wait_ms;
  unsigned int time_spent = 0;
  int result;
  assert(dcaf_context);
  assert(transaction);
  wait_ms = dcaf_context->timeout_ms;

  ctx = dcaf_get_coap_context(dcaf_context);
  assert(ctx);

  while (!done) {
    unsigned int timeout = wait_ms == 0 ? 5000 : wait_ms;

    /* coap_io_process() returns the time in milliseconds it has
     * spent. We use this value to determine if we have run out of
     * time. */
#if !defined(LIBCOAP_VERSION) || (LIBCOAP_VERSION < 4003000)
    result = coap_run_once(ctx, timeout);
#else /* LIBCOAP_VERSION >= 4003000 */
    result = coap_io_process(ctx, timeout);
#endif  /* LIBCOAP_VERSION >= 4003000 */
    dcaf_log(DCAF_LOG_DEBUG, "coap_run_once returns %d\n", result);

    if (result < 0) { /* error */
      dcaf_log(DCAF_LOG_ERR, "CoAP error\n");
      /* TODO: remove transaction */
      break;
    } else { /* check for potential timeout */
      if (time_spent + result >= timeout) {
        dcaf_log(DCAF_LOG_INFO, "timeout\n");
        /* TODO: cancel transaction? */
        break;
      }
      time_spent += result;
      /* TODO: check done only if transaction has ended. */
      done = !dcaf_check_transaction(dcaf_context, transaction)
        || (transaction->state.act == DCAF_STATE_AUTHORIZED);

      if (done)
        dcaf_log(DCAF_LOG_INFO, "DCAF transaction finished\n");
    }
  }
}

dcaf_transaction_t *
dcaf_send_request_uri(dcaf_context_t *dcaf_context,
                      int code,
                      const coap_uri_t *uri,
                      dcaf_optlist_t options,
                      const uint8_t *data,
                      size_t data_len,
                      dcaf_application_handler_t app_hnd,
                      int flags) {
  coap_context_t *ctx;
  int result;
  coap_address_t dst;
  coap_pdu_t *pdu;
  coap_session_t *session;
  uint8_t token[DCAF_DEFAULT_TOKEN_SIZE];
  dcaf_transaction_t *t = NULL;

  assert(dcaf_context);
  assert(uri);

  ctx = dcaf_get_coap_context(dcaf_context);
  assert(ctx);

    /* set remote address from uri->host */
  result = dcaf_set_coap_address(uri->host.s, uri->host.length,
                                 uri->port, &dst);
  if (result < 0) {
    dcaf_log(DCAF_LOG_ERR, "cannot resolve URI host '%.*s'\n",
             (int)uri->host.length, uri->host.s);
    return NULL;
  }

  /* check if we have an ongoing session with this peer */
  if (!(session = coap_session_get_by_peer(ctx, &dst, 0 /* ifindex */))) {
    /* no session available, create new */
    if (coap_uri_scheme_is_secure(uri)) {
      dcaf_key_t *k = dcaf_find_key(dcaf_context, &dst, NULL, 0);
      char identity[DCAF_MAX_KID_SIZE+1];

      if (!k) {
        dcaf_log(DCAF_LOG_ERR, "cannot find credentials for %.*s\n",
                 (int)uri->host.length, uri->host.s);
        return NULL;
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
    return NULL;
  }

  pdu = coap_new_pdu(COAP_MESSAGE_CON, code, session);
  if (!pdu) {
    dcaf_log(DCAF_LOG_WARNING, "cannot create new PDU\n");
    return NULL;
  }

  /* generate random token */
  if (!dcaf_prng(token, sizeof(token))
      || !coap_add_token(pdu, sizeof(token), token)) {
    dcaf_log(DCAF_LOG_DEBUG, "cannot add token to request\n");
    goto error;
  }

  /* insert URI options for request */
  set_uri_options(uri, COAP_OPTION_URI_PATH, &options);
  set_uri_options(uri, COAP_OPTION_URI_QUERY, &options);
  coap_add_optlist_pdu(pdu, (coap_optlist_t **)&options);

  if (data && data_len && !coap_add_data(pdu, data_len, data)) {
      dcaf_log(DCAF_LOG_WARNING, "cannot set payload\n");
  }

  t = dcaf_create_transaction(dcaf_context, session, pdu);
  if (!t) {
    dcaf_log(DCAF_LOG_WARNING, "cannot create new transaction\n");
    goto error;
  }
  {
    const char aud_prefix[] = { 'c', 'o', 'a', 'p', 's', ':', '/', '/' };
    t->aud.s = dcaf_alloc_type_len(DCAF_STRING, uri->host.length + sizeof(aud_prefix));
    if (t->aud.s) {
      t->aud.length = uri->host.length + sizeof(aud_prefix);
      memcpy(t->aud.s, aud_prefix, sizeof(aud_prefix));
      memcpy(t->aud.s + sizeof(aud_prefix), uri->host.s, uri->host.length);
    } else {
      memset(&t->aud, 0, sizeof(t->aud));
      dcaf_log(DCAF_LOG_WARNING, "cannot store aud info: buffer too small.\n");
    }
  }
  t->flags = flags;
  t->application_handler = app_hnd;
  dcaf_log(DCAF_LOG_DEBUG, "added transaction %02x%02x%02x%02x\n",
           t->tid[0], t->tid[1], t->tid[2], t->tid[3]);

  /* Store remote address in transaction object. We need to adjust the
   * port to switch to DTLS later. */
  coap_address_copy(&t->remote, coap_session_get_addr_remote(session));
  if (!coap_uri_scheme_is_secure(uri)) {
    uint16_t port = dcaf_get_coap_port(&t->remote);
    dcaf_set_coap_port(&t->remote, port ? port + 1 : COAPS_DEFAULT_PORT);
  }

  coap_send(session, pdu);

  /* Wait until transaction has finished if DCAF_TRANSACTION_BLOCK
   * flag is set. */
  if (flags & DCAF_TRANSACTION_BLOCK) {
    dcaf_loop_io(dcaf_context, t);
  }

  return t;
 error:
  coap_free(pdu);
  return NULL;
}

dcaf_transaction_t *
dcaf_send_request(dcaf_context_t *dcaf_context,
                  int code,
                  const char *uri_str,
                  size_t uri_len,
                  dcaf_optlist_t options,
                  const uint8_t *data,
                  size_t data_len,
                  dcaf_application_handler_t app_hnd,
                  int flags) {
  unsigned char buf[uri_len];
  coap_uri_t uri;

  assert(uri_len > 0);
  memcpy(buf, uri_str, uri_len);

  if (coap_split_uri(buf, uri_len, &uri) < 0) {
    dcaf_log(DCAF_LOG_ERR, "cannot process request URI\n");
    return NULL;
  }

  return dcaf_send_request_uri(dcaf_context, code, &uri, options,
                               data, data_len, app_hnd, flags);
}
#undef min
