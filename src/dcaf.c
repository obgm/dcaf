/*
 * dcaf.c -- libdcaf core
 *
 * Copyright (C) 2015-2021 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2021 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "dcaf_config.h"
#define DCAF_UTF8ENCODE_PSKIDENTITY 1
#define DCAF_MAX_PSK_IDENTITY 256

#ifdef RIOT_VERSION
#include "libcoap_init.h"
#ifdef MODULE_PRNG
#include "random.h"
#endif /* MODULE_PRNG */
#endif /* RIOT_VERSION */

#include "dcaf/anybor.h"
#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/state.h"
#include "dcaf/utlist.h"

#if DCAF_UTF8ENCODE_PSKIDENTITY
#include "dcaf/dcaf_utf8.h"
#endif

#include "dcaf/aif.h"
#include "dcaf/cwt.h"

void
dcaf_init(void) {
#if defined(RIOT_VERSION) && defined(MODULE_PRNG)
  dcaf_set_prng(random_bytes);
#endif /* RIOT_VERSION && MODULE_PRNG */
}

static inline uint8_t
coap_get_token_len(coap_pdu_t *p) {
  return p->token_length;
}

static inline int
token_equals(coap_pdu_t *a, coap_pdu_t *b) {
  if (a && b) {
    unsigned atkl = coap_get_token_len(a);
    unsigned btkl = coap_get_token_len(b);
    return (atkl == btkl)
      && (strncmp((char *)a->token, (char *)b->token, atkl) == 0);
  }
  return 0;
}

#if DCAF_CLIENT
/* Returns true iff DCAF should be used. */
static bool
is_dcaf(int content_format) {
  return (content_format == -1)
    || (content_format == DCAF_MEDIATYPE_DCAF_CBOR);
}
#endif /* DCAF_CLIENT */

/**
 * Utility function to extract a COSE_Key from @p obj skipping the
 * CBOR tag if present.  This function returns a pointer to the
 * CBOR structure representing the actual COSE_Key, or NULL on
 * error.
 */
static inline abor_decoder_t *
get_cose_key(abor_decoder_t *obj) {
  assert(obj);

  obj = abor_mapget_int(obj, CWT_CNF_COSE_KEY);

  /* consume COSE_KEY tag if present */
  abor_consume_tag(obj, COSE_KEY);

  return obj;
}

#if 0
static dcaf_transaction_result_t
access_response_handler(dcaf_context_t *dcaf_context,
                        dcaf_transaction_t *t,
                        coap_pdu_t *received) {
  (void)dcaf_context;
  (void)received;
  dcaf_log(DCAF_LOG_DEBUG, "handle response from AM\n");
  /* TODO: parse response to access request
   *       must be DCAF
   *         on success, proceed with t->future
   *         on error, make t->future fail as well
   *       indicate via result if transaction can be deleted?
   */

  if (t->state.future) {
    /* if we are done, deliver to future's deliver handler (or so) */
  }
  return DCAF_TRANSACTION_OK;
}
#endif

#if 0
static void
am_error_handler(dcaf_context_t *dcaf_context,
                 dcaf_transaction_t *t,
                 int error) {
  (void)dcaf_context;
  (void)t;
  dcaf_log(DCAF_LOG_DEBUG, "AM error %d\n", error);
}
#endif

#if DCAF_CLIENT
static size_t
make_ticket_request(const dcaf_transaction_t *transaction,
                    const uint8_t *data, size_t data_len,
                    uint8_t *result, size_t max_result_len) {
  abor_encoder_t *abc;
  abor_decoder_t *abd, *iss, *snc;
  size_t len;
  uint8_t buf[DCAF_MAX_RESOURCE_LEN+1];
  size_t length = sizeof(buf);
  size_t num_items = 2; /* audience and scope */
  if (!transaction || abor_get_major_type(data) != ABOR_MAP) {
    return 0;
  }

  abc = abor_encode_start(result, max_result_len);
  abd = abor_decode_start(data, data_len);
  if (!abc || !abd) {
    abor_encode_finish(abc);
    abor_decode_finish(abd);
    return 0;
  }

  iss = abor_mapget_int(abd, DCAF_REQ_SAM);
  snc = abor_mapget_int(abd, DCAF_REQ_SNC);

  num_items += (iss != NULL) + (snc != NULL) + ACE_REQUEST_PROFILE;
  abor_write_map(abc, num_items);

  /* issuer */
  if (iss && abor_write_int(abc, DCAF_REQ_SAM)) {
    abor_copy_item(iss, abc);
  }

  /* audience */
  abor_write_int(abc, DCAF_REQ_AUD);

  if (transaction->aud.length > 0) {
    abor_write_text(abc, transaction->aud.s, transaction->aud.length);
  }

  /* scope */
  abor_write_int(abc, DCAF_REQ_SCOPE);
  abor_write_array(abc, 2);
  /* create scope from initial request data */
  if (coap_get_resource_uri(transaction->pdu, buf, &length, 0)) {
    assert(buf[length] == 0);
    abor_write_text(abc, (char *)buf, length);
    abor_write_uint(abc, coap_get_method(transaction->pdu));
  }

  /* optional ace_profile */
  if (ACE_REQUEST_PROFILE) {
      abor_write_int(abc, ACE_MSG_PROFILE);
      abor_write_null(abc);
  }

  /* snc */
  if (snc && abor_write_int(abc, DCAF_REQ_SNC)) {
    abor_copy_item(snc, abc);
  }
  
  abor_decode_finish(iss);
  abor_decode_finish(snc);
  len = abor_encode_finish(abc);
  abor_decode_finish(abd);

  return len;  
}
#endif /* DCAF_CLIENT */

#if DCAF_CLIENT
static void
handle_unauthorized(dcaf_context_t *dcaf_context,
                    dcaf_transaction_t *t,
                    coap_pdu_t *received) {
  uint8_t *data;
  size_t data_len;
  dcaf_transaction_t *am_t;

#define DCAF_TRANSACTION_ERR_MAX 1
  if (++t->state.err_cnt > DCAF_TRANSACTION_ERR_MAX) {
    dcaf_log(DCAF_LOG_DEBUG,
             "reached failure threshold for transaction\n");

    /* invoke error callback if set */
    if (t->error_handler) {
      t->error_handler(dcaf_context, t, DCAF_ERROR_UNAUTHORIZED_THRESHOLD);
    }
    dcaf_delete_transaction(dcaf_context, t);
    return;
  }

  coap_get_data(received, &data_len, &data);

  if (data_len > 0) {
    uint8_t ticket_req[512];
    size_t len;

    len = make_ticket_request(t, data, data_len,
                              ticket_req, sizeof(ticket_req));
    if (len > 0) {
      /* FIXME: Set Content-Format to DCAF_MEDIATYPE_DCAF_CBOR */
      /* pass SAM response to AM */
      dcaf_log(DCAF_LOG_DEBUG, "pass DCAF Unauthorized response to AM\n");
      am_t = dcaf_send_request_uri(dcaf_context, COAP_REQUEST_POST,
                                   dcaf_context->am_uri,
                                   NULL /* optlist */,
                                   ticket_req, len,
                                   NULL,
                                   DCAF_TRANSACTION_NONBLOCK);
      if (am_t) {
        dcaf_log(DCAF_LOG_DEBUG, "am_t is %02x%02x%02x%02x\n",
                 am_t->tid[0], am_t->tid[1], am_t->tid[2], am_t->tid[3]);
        am_t->state.act = DCAF_STATE_ACCESS_REQUEST;
        am_t->state.type = DCAF_TRANSACTION_SYSTEM;
        am_t->state.future = t;
        /* am_t->response_handler = access_response_handler; */
        /* am_t->error_handler = am_error_handler; */
      }
    } else {
    dcaf_log(DCAF_LOG_ERR, "cannot create ticket request\n");
    dcaf_delete_transaction(dcaf_context, t);
    }
  } else {
    dcaf_log(DCAF_LOG_ERR, "No SAM info in unauthorized response\n");
    dcaf_delete_transaction(dcaf_context, t);
  }
}
#endif /* DCAF_CLIENT */

#if DCAF_CLIENT
static void
handle_ticket_transfer(dcaf_context_t *dcaf_context,
                       dcaf_transaction_t *t,
                       coap_pdu_t *received) {
  size_t content_len = 0;
  uint8_t *content = NULL;
  abor_decoder_t *cbor;
  abor_decoder_t *cnf;
  abor_decoder_t *cose_key = NULL;
  dcaf_ticket_t *cinfo = NULL;
  dcaf_key_type key_type = DCAF_NONE;

  (void)received;

  dcaf_log(DCAF_LOG_DEBUG, "handle ticket transfer\n");

  /* This function is called from handle_coap_response() after
   * checking the correct Content-Format for dcaf. Thus, we do not
   * need to check again.
   */

  assert(t);
  /* Parse ticket from message content and add to ticket store. */

  if (!coap_get_data(received, &content_len, &content)) {
    dcaf_log(DCAF_LOG_ERR, "no ticket found in received message\n");
    return;
  }

#if defined(ABOR_STATIC_MAPGET_NUM_ITEMS) && (ABOR_STATIC_MAPGET_NUM_ITEMS < (4U))
#error ABOR_STATIC_MAPGET_NUM_ITEMS must be at least 4
#endif /* ABOR_STATIC_MAPGET_NUM_ITEMS >= 4 */

  /* A constrained application may parse on-demand, i.e. treat the
   * ticket_face as opaque. */
  cbor = abor_decode_start(content, content_len);
  if (!cbor) {
    dcaf_log(DCAF_LOG_ERR, "cannot parse ticket\n");
    return;
  }

  if (DCAF_CLIENT_VALIDITY_OPTION == 1) {
    abor_decoder_t *iat, *lt;
    uint64_t timestamp;
    uint64_t lifetime = COAP_DEFAULT_MAX_AGE;
    dcaf_time_t now = dcaf_gettime();

    iat = abor_mapget_int(cbor, DCAF_CINFO_IAT);

    /* read mandatory iat field */
    if (!iat) {
      dcaf_log(DCAF_LOG_INFO, "no iat found (validity option 1)\n");
      goto finish;
    }
    if (((abor_get_type(iat) == ABOR_TAG) && !abor_consume_tag(iat, 1))
        || !abor_get_uint(iat, &timestamp)) {
      dcaf_log(DCAF_LOG_INFO, "invalid value in iat\n");
      abor_decode_finish(iat);
      goto finish;
    }
    abor_decode_finish(iat);

    /* Read lifetime. If not present, set lifetime to Max-Age. */
    lt = abor_mapget_int(cbor, DCAF_CINFO_EXPIRES_IN);
    if (lt) {
      if (!abor_get_uint(lt, &lifetime)) {
        dcaf_log(DCAF_LOG_INFO, "invalid value in lt\n");
        abor_decode_finish(lt);
        goto finish;
      }
      abor_decode_finish(lt);
    } else { /* use Max-Age as lifetime */
      coap_opt_t *max_age;
      coap_opt_iterator_t opt_iter;

      max_age = coap_check_option(received, COAP_OPTION_MAXAGE, &opt_iter);
      if (max_age) {
        lifetime = coap_decode_var_bytes(coap_opt_value(max_age),
                                         coap_opt_length(max_age));
      }
    }

    /* The remaining lifetime RL is calculated as LT - (CT - AM_TS). */
    if (((uint64_t)now < timestamp) || lifetime < (now - timestamp)) {
        dcaf_log(DCAF_LOG_INFO, "ticket has already expired\n");
        goto finish;
    }
  }

  /* get key from cbor and use ticket face as psk for new session: */

  /* retrieve cnf containg keying material information */
  cnf = abor_mapget_int(cbor, DCAF_CINFO_CNF);
  if (!cnf) {
    dcaf_log(DCAF_LOG_INFO, "no cnf found\n");
    goto finish;
  }

  /* FIXME:
  seq = abor_mapget_int(cbor, DCAF_CINFO_SEQ);
  */
  cinfo = dcaf_new_ticket(key_type, 0 /* FIXME: seq->v.uint */,
                          0 /* FIXME: now */,
                          1000 /* FIXME: remaining_ltm */);
  
  cose_key = get_cose_key(cnf); /* extract cose key object */
  abor_decode_finish(cnf);
  if (!cose_key) {
    dcaf_log(DCAF_LOG_INFO, "no COSE_Key found\n");
    goto finish;
  }
  dcaf_parse_dcaf_key(cinfo->key, cose_key);
  abor_decode_finish(cose_key);
  dcaf_log(DCAF_LOG_DEBUG, "we have a key!\n");

  if (dcaf_check_transaction(dcaf_context, t->state.future)) {
    coap_address_t remote;
    /* The future transaction can be completed with the access
     * ticket we have received. We need to create a coaps session
     * with the ticket face as identity and the contained key
     * as PSK.
     */
    if (t->state.future->state.type == DCAF_TRANSACTION_AUTO) {
      /* FIXME: set from aud */
      dcaf_set_coap_address((const unsigned char *)"192.168.0.30", 12, 5684, &remote);
    } else {
      coap_address_copy(&remote, &t->state.future->remote);
    }
    /* FIXME: encapsulate in dcaf_send...something() */
#if LIBCOAP_VERSION >= 4003000U
    coap_dtls_cpsk_t setup_data;
#endif /* LIBCOAP_VERSION >= 4003000 */
    const uint8_t *raw_identity = NULL;
    uint8_t *identity = NULL;
    size_t identity_len;
    coap_session_t *session;
    coap_context_t *ctx;
    abor_decoder_t *ticket_face;
    size_t ticket_face_length;
    const uint8_t *ticket_face_data;

    ctx = dcaf_get_coap_context(dcaf_context);
    assert(ctx);

    ticket_face = abor_mapget_int(cbor, DCAF_CINFO_TICKET_FACE);
    if (!ticket_face) {
      dcaf_log(DCAF_LOG_INFO, "cannot find ticket face\n");
      goto finish;
    }

    ticket_face_length = abor_get_sequence_length(ticket_face);
    ticket_face_data = abor_get_bytes(ticket_face);
    abor_decode_finish(ticket_face);
    if (!ticket_face_length || !ticket_face_data) {
      dcaf_log(DCAF_LOG_INFO, "invalid ticket face\n");
      goto finish;
    }
#if DCAF_UTF8ENCODE_PSKIDENTITY
    identity_len = utf8_length(ticket_face_data, ticket_face_length);
    identity = dcaf_alloc_type_len(DCAF_STRING, identity_len + 1);
    if (!identity || !uint8_to_utf8((char *)identity, &identity_len,
                                    ticket_face_data, ticket_face_length)) {
      dcaf_log(DCAF_LOG_WARNING, "Cannot encode ticket face. Sending raw.");
      identity_len = ticket_face_length;
      raw_identity = ticket_face_data;
    }
#else /* !DCAF_UTF8ENCODE_PSKIDENTITY */
    identity_len = ticket_face_length;
    raw_identity = ticket_face_data;
#endif /* !DCAF_UTF8ENCODE_PSKIDENTITY */

#if !defined(LIBCOAP_VERSION) || (LIBCOAP_VERSION < 4003000U)
    /* coap_new_client_session_psk() requires identity to be
     * zero-terminated, hence we cannot use the raw_identity. identity
     * has been allocated to provide one additional byte for the
     * terminating zero. */
    if (!identity) {
        dcaf_log(DCAF_LOG_CRIT, "cannot setup identity for DTLS session\n");
        goto finish;
    }
    identity[identity_len] = '\000';
    session = coap_new_client_session_psk(ctx, NULL,
                                          &remote,
                                          COAP_PROTO_DTLS,
                                          (const char *)identity,
                                          cinfo->key->data,
                                          cinfo->key->length);
#else /* LIBCOAP_VERSION >= 4003000 */
    memset(&setup_data, 0, sizeof(setup_data));
    setup_data.version = COAP_DTLS_CPSK_SETUP_VERSION;

    COAP_SET_STR(&setup_data.psk_info.identity, identity_len, identity ? identity : raw_identity);
    COAP_SET_STR(&setup_data.psk_info.key, cinfo->key->length, cinfo->key->data);

    session = coap_new_client_session_psk2(ctx, NULL,
                                           &remote,
                                           COAP_PROTO_DTLS,
                                           &setup_data);
#endif /* LIBCOAP_VERSION >= 4003000 */
    assert(DCAF_UTF8ENCODE_PSKIDENTITY || identity == NULL);
    dcaf_free_type(DCAF_STRING, identity);

    /* TODO: dcaf_create_transaction... */
    assert(session);
    if (session) {
      coap_pdu_t *pdu = coap_new_pdu(session);
      uint8_t token[4];
      coap_opt_iterator_t opt_iter;
      coap_opt_filter_t f;
      coap_opt_t *q;
      uint16_t type = 0;

      pdu->type = COAP_MESSAGE_CON;
      pdu->tid = coap_new_message_id(session);
      pdu->code = COAP_REQUEST_GET;
      if (!dcaf_prng(token, sizeof(token))
          || !coap_add_token(pdu, sizeof(token), token)) {
      }

      /* copy URI options for request */
      if (t->state.future->pdu) {
#if LIBCOAP_VERSION >= 4003000U
        coap_option_filter_clear(&f);
#else
        coap_option_filter_clear(f);
#endif /* LIBCOAP_VERSION >= 4003000 */
        coap_option_iterator_init(t->state.future->pdu, &opt_iter, COAP_OPT_ALL);

        while ((q = coap_option_next(&opt_iter))) {
          coap_option_t parsed_option;
          if (!coap_opt_parse(q, coap_opt_size(q), &parsed_option)) {
            break;
          }
          type += parsed_option.delta;
          coap_add_option(pdu, type, parsed_option.length, parsed_option.value);
        }
      } else if (t->state.future->state.type == DCAF_TRANSACTION_AUTO) {
        /* TODO: get scope from client info */
        coap_add_option(pdu, COAP_OPTION_URI_PATH, 10, (const uint8_t *)"restricted");
      }
      dcaf_transaction_update(t->state.future, session, pdu);
      coap_send(session, pdu);

      if (dcaf_check_transaction(dcaf_context, t->state.future) && (t->state.future->flags & DCAF_TRANSACTION_BLOCK)) {
        dcaf_loop_io(dcaf_context, t->state.future);
      }
    }
  }
 finish:
  abor_decode_finish(cbor);
  dcaf_free_ticket(cinfo);
}
#endif /* DCAF_CLIENT */

#if DCAF_CLIENT
#if LIBCOAP_VERSION >= 4003000U
#define COAP_RESPONSE_T coap_response_t
#else
#define COAP_RESPONSE_T void
#define COAP_RESPONSE_OK
#endif /* LIBCOAP_VERSION >= 4003000U */

static COAP_RESPONSE_T
handle_coap_response(struct coap_context_t *coap_context,
                     coap_session_t *session,
                     coap_pdu_t *sent,
                     coap_pdu_t *received,
                     const coap_tid_t id) {
  dcaf_context_t *dcaf_context;
  dcaf_transaction_t *t;
  bool deliver = false;
  uint8_t code;

  (void)sent;
  (void)id;

  dcaf_context = dcaf_get_dcaf_context(coap_context);
  assert(dcaf_context);

  t = dcaf_find_transaction(dcaf_context, session, received);
  if (!t) {
    dcaf_log(DCAF_LOG_ERR, "dropped response for unknown transaction\n");
    return COAP_RESPONSE_OK;
  }

  /* Call response handler or error handler, respectively. If not set,
   * this is the initial transaction that will be handled manually. */
  code = coap_get_response_code(received);
  if (t->response_handler) {
    dcaf_log(DCAF_LOG_DEBUG, "invoke response handler\n");
    t->response_handler(dcaf_context, t, received);
    dcaf_delete_transaction(dcaf_context, t);
    return COAP_RESPONSE_OK;
  }

  /* Reached only for responses that have no handler, i.e., the
   * default behavior. */

  if (!is_dcaf(coap_get_content_format(received))) {
    dcaf_log(DCAF_LOG_INFO, "received non-dcaf response\n");
    /* FIXME: application delivery */
    if (t->application_handler)
      t->application_handler(dcaf_context, t, received);
    dcaf_delete_transaction(dcaf_context, t);
    return COAP_RESPONSE_OK;
  }

  /* pretty-print CBOR payload if debug is enabled */
  if (dcaf_get_log_level() >= DCAF_LOG_DEBUG) {
    uint8_t *data;
    size_t data_len;

    if (coap_get_data(received, &data_len, &data)) {
      dcaf_show_cbor(data, data_len);
    }
  }

  switch (t->state.act) {
  case DCAF_STATE_IDLE: {
    /* FIXME: check response code, handle DCAF SAM response
              deliver message in any other case */
    if (code == COAP_RESPONSE_CODE_UNAUTHORIZED) {
      handle_unauthorized(dcaf_context, t, received);
    } else {           /* handle final response for transaction t */
      dcaf_log(DCAF_LOG_DEBUG, "received final response with code %u\n",
               code);
      if (!t->state.future && (t->state.type == DCAF_TRANSACTION_USER)) {
        /* TODO: if sent pdu was not an empty dcaf+cbor message then
         * deliver final response to the application
         * handler. Otherwise, do the fake access request. */

        /* fake access request */
        t->state.future = dcaf_create_transaction(dcaf_context, session, NULL);
        if (!t->state.future) {
          dcaf_log(DCAF_LOG_WARNING, "cannot allocate DCAF transaction\n");
        } else {
          t->state.future->state.act = DCAF_STATE_ACCESS_REQUEST;
          t->state.future->state.type = DCAF_TRANSACTION_AUTO;
          /* pass flags and application_handler on to future transaction */
          t->state.future->flags = t->flags;
          t->state.future->application_handler = t->application_handler;
        }
      }
      if (dcaf_check_transaction(dcaf_context, t->state.future) &&
          (t->state.future->state.act == DCAF_STATE_ACCESS_REQUEST)) {
        handle_ticket_transfer(dcaf_context, t, received);
        t->state.act = DCAF_STATE_AUTHORIZED; /* Finished? */
        t->state.future->state.act = DCAF_STATE_TICKET_GRANT;
      }
      return COAP_RESPONSE_OK;
    }
    break;
  }
  case DCAF_STATE_ACCESS_REQUEST:
    /* Handle response to previous access request */

    if (COAP_RESPONSE_CLASS(code) == 2) {
      handle_ticket_transfer(dcaf_context, t, received);
      t->state.act = DCAF_STATE_AUTHORIZED;
      return COAP_RESPONSE_OK;
    } else {                  /* access request failed */
      /* FIXME: signal error to application */
      dcaf_log(DCAF_LOG_CRIT, "access request failed\n");
      dcaf_delete_transaction(dcaf_context, t);
      return COAP_RESPONSE_OK;
    }
    break;
  case DCAF_STATE_TICKET_REQUEST:
    /* fall through */
  case DCAF_STATE_TICKET_GRANT:
    /* fall through */
  case DCAF_STATE_AUTHORIZED:
    /* fall through */
  case DCAF_STATE_UNAUTHORIZED:
    /* fall through */
  default:
    dcaf_log(DCAF_LOG_ALERT, "unknown transaction state\n");
    return COAP_RESPONSE_OK;
  }

  if (deliver && t && t->response_handler) {
    t->response_handler(dcaf_context, t, received);
  }
  return COAP_RESPONSE_OK;
}
#endif /* DCAF_CLIENT */

static int
set_endpoint(const dcaf_context_t *dcaf_context,
             const coap_address_t *addr,
             coap_proto_t proto) {
  return coap_new_endpoint(dcaf_context->coap_context, addr, proto) != NULL;
}

dcaf_time_t dcaf_gettime(void) {
  coap_tick_t now;
  coap_ticks(&now);
  return coap_ticks_to_rt(now);
}

dcaf_nonce_t *dcaf_nonces = NULL;
/* TODO: store list per AM? */
dcaf_ticket_t *dcaf_tickets = NULL;
dcaf_dep_ticket_t *deprecated_tickets = NULL;


void
dcaf_expiration(void) {
  dcaf_ticket_t *ticket=NULL, *temp = NULL;
  dcaf_dep_ticket_t *dep_ticket=NULL, *tempp = NULL;
  dcaf_nonce_t *nonce=NULL, *temppp = NULL;
  /* search ticket list for expired tickets */
  dcaf_time_t now = dcaf_gettime();
  LL_FOREACH_SAFE(dcaf_tickets, ticket, temp){
    if ((ticket->ts+ticket->remaining_time)<=now) {
      dcaf_log(DCAF_LOG_DEBUG, "ticket for session %p has expired\n",
               ticket->session);
      dcaf_remove_ticket(ticket);
    }
  }
  /* search deprecated tickets for expired tickets */
  LL_FOREACH_SAFE(deprecated_tickets, dep_ticket,tempp) {
    if ((dep_ticket->ts+dep_ticket->remaining_time)<=now) {
      LL_DELETE(deprecated_tickets, dep_ticket);
      dcaf_free_type(DCAF_DEP_TICKET, dep_ticket);
    }
  }
  LL_FOREACH_SAFE(dcaf_nonces, nonce, temppp) {
    if (nonce->validity_type==2) {
      if ((nonce->validity_value.dat+DCAF_MAX_SERVER_TIMEOUT)>now) {
	LL_DELETE(dcaf_nonces,nonce);
	dcaf_free_type(DCAF_NONCE, nonce);
      }
    }
    else {
      /* FIXME: function may not be called once per minute, so fix timer++ */
      if ((nonce->validity_value.timer++)>=DCAF_MAX_SERVER_TIMEOUT) {
	LL_DELETE(dcaf_nonces,nonce);
	dcaf_free_type(DCAF_NONCE, nonce);
      }
    }
  }
}


/* we could define a method that deletes all tickets, deprecated
   tickets and nonces before sleeping, but sleeping takes care of this
   problem anyway */
/* void */
/* dcaf_prepare_sleep() { */
/*   if (DCAF_SERVER_VALIDITY_OPTION==3) { */    
/*   } */
/* } */

static dcaf_ticket_t *
dcaf_find_ticket(const coap_session_t *session) {
  dcaf_ticket_t *ticket = NULL;
  LL_SEARCH_SCALAR(dcaf_tickets, ticket, session, session);
  if (ticket) {
    dcaf_log(DCAF_LOG_DEBUG, "found ticket for session %p\n",
             ticket->session);
  } else {
    dcaf_log(DCAF_LOG_DEBUG, "no ticket for session %p found\n",
             (void *)session);
  }
  return ticket;
}

dcaf_ticket_t *
dcaf_new_ticket(const dcaf_key_type key_type,
		const unsigned long seq, const dcaf_time_t ts,
		const uint32_t remaining_time) {

  dcaf_ticket_t *ticket = (dcaf_ticket_t *)dcaf_alloc_type(DCAF_TICKET);
  if (ticket) {
    memset(ticket, 0, sizeof(dcaf_ticket_t));
    ticket->seq = seq;
    ticket->ts = ts;
    ticket->remaining_time = remaining_time;
    ticket->key = dcaf_new_key(key_type);
  }
  /* TODO: do we need to reserve storage space for aif? */
  return ticket;
}

dcaf_dep_ticket_t *
dcaf_new_dep_ticket(const unsigned long seq, const dcaf_time_t ts,
		    const uint32_t remaining_time) {
  dcaf_dep_ticket_t *ticket = (dcaf_dep_ticket_t*)dcaf_alloc_type(DCAF_DEP_TICKET);
  if (ticket) {
    memset(ticket, 0, sizeof(dcaf_dep_ticket_t));
    ticket->seq = seq;
    ticket->ts = ts;
    ticket->remaining_time = remaining_time;
  }
  return ticket;
}

dcaf_nonce_t *
dcaf_new_nonce(size_t len) {
  dcaf_nonce_t *nonce = (dcaf_nonce_t*)dcaf_alloc_type(DCAF_NONCE);
  if (nonce) {
    memset(nonce, 0, sizeof(dcaf_nonce_t));
    nonce->nonce_length = len;
  }
  return nonce;
}


void
dcaf_remove_ticket(dcaf_ticket_t *ticket) {
  if (ticket) {
    LL_DELETE(dcaf_tickets,ticket);
    dcaf_free_ticket(ticket);
  }
}

void
dcaf_add_ticket(dcaf_ticket_t *ticket) {
  if (ticket) {
    LL_PREPEND(dcaf_tickets, ticket);
  }
}

void
dcaf_free_ticket(dcaf_ticket_t *ticket) {
  if (ticket) {
    dcaf_free_type(DCAF_AIF, ticket->aif);
    dcaf_free_type(DCAF_KEY, ticket->key);
    dcaf_free_type(DCAF_TICKET, ticket);
  }
}

void
dcaf_parse_dcaf_key(dcaf_key_t *key, const abor_decoder_t* cose_key) {
  if (cose_key && key) {
    abor_decoder_t *obj;
    uint64_t alg;
    /* set kid */
    obj = abor_mapget_int(cose_key,COSE_KEY_KID);
    if (obj) {
      key->kid_length = DCAF_MAX_KID_SIZE;
      if (!abor_copy_bytes(obj, key->kid, &key->kid_length)) 
        key->kid_length = 0;
    }
    abor_decode_finish(obj);

    /* set algorithm */
    obj = abor_mapget_int(cose_key,COSE_KEY_ALG);
    if (obj && abor_get_uint(obj, &alg)) {
      switch (alg) {
      case COSE_AES_CCM_64_64_128:
	key->type=DCAF_AES_128;
	break;
	/* TODO: other cases */
      default:
	;
      }
    }
    abor_decode_finish(obj);
    
    /* set key */
    obj = abor_mapget_int(cose_key,COSE_KEY_K);
    if (obj) {
      key->length = DCAF_MAX_KEY_SIZE;
      if (!abor_copy_bytes(obj, key->data, &key->length)) 
        key->length = 0;
    }
    abor_decode_finish(obj);  
  }
}

int dcaf_determine_offset_with_nonce(const uint8_t *nonce, size_t nonce_size){
  int offset = -1;
  int res;
  dcaf_nonce_t *stored_nonce=NULL;

  /* search stored nonces for nonce */
  LL_FOREACH(dcaf_nonces,stored_nonce) {
    if (nonce_size == stored_nonce->nonce_length) {
      res = memcmp(nonce, stored_nonce->nonce, nonce_size);
      if (res) {
	/* nonce found */
	if (stored_nonce->validity_type==2) {
	  dcaf_time_t dat = stored_nonce->validity_value.dat;
	  dcaf_time_t now;
	  /* if timestamp is found,
	     offset = current-time - timestamp */
	  now = dcaf_gettime();
	  offset = now - dat;
	}
	else if (stored_nonce->validity_type==3) {
	  /* if a timer is found, offset = already passed time */
	  offset = stored_nonce->validity_value.timer;
	}
      }
    }
  }
  
  if (offset == -1) {
    dcaf_log(DCAF_LOG_INFO, "no such nonce found in stored nonces\n");
  }
  return offset;
}

static const dcaf_key_t *
get_am_key(const char *kid, size_t kid_length, cose_mode_t mode, void *arg) {
  dcaf_context_t *dcaf_context = (dcaf_context_t *)arg;

  if ((mode != COSE_MODE_DECRYPT) || !dcaf_context) {
    return NULL;
  }

  return dcaf_find_key(dcaf_context, NULL, (const uint8_t *)kid, kid_length);
}

#define MAJOR_TYPE_MASK     (0xE0) /* 0b111_00000 */

enum {
      CBOR_MAJOR_TYPE_ARRAY=4,
      CBOR_MAJOR_TYPE_MAP=5,
      CBOR_MAJOR_TYPE_TAG=6,
};

static inline int
cbor_major_type(const uint8_t b) {
  return (b & MAJOR_TYPE_MASK) >> 5;
}

static inline int
get_cbor_tag(const uint8_t *data, size_t length) {
  if (data && (length > 0)) {
    if (cbor_major_type(data[0]) == CBOR_MAJOR_TYPE_TAG) {
      /* FIXME: handle multi-byte values */
      return data[0] & ~MAJOR_TYPE_MASK;
    }
  }
  return -1;
}

static inline bool
maybe_cose(const uint8_t *data, size_t length) {
  int tag = get_cbor_tag(data, length);
  /* for now, only tag COSE_Encrypt0 is recognized */
  if (tag == COSE_ENCRYPT0) {
    data++;
    length--;
    tag = -1;                   /* indicate that tag was handled */
  }
  /* data may be NULL if tag == -1 */
  if (data && (tag == -1) && (length > 1)) {
    return abor_get_major_type(data) == ABOR_ARRAY;
  }
  return 0;
}

static dcaf_context_t *
get_dcaf_context_from_session(const coap_session_t *session) {
  if (session && session->context) {
    return dcaf_get_dcaf_context(session->context);
  }
  return NULL;
}

static inline bool
check_lifetime(int remaining_ltm) {
  if (remaining_ltm <= 0) {
    dcaf_log(DCAF_LOG_INFO, "ticket lifetime exceeded\n");
    return false;
  }
  return true;
}

#if DCAF_SERVER
dcaf_result_t
dcaf_parse_ticket_face(const coap_session_t *session,
                  const uint8_t *data, size_t data_len,
                  dcaf_ticket_t **result) {
  dcaf_result_t res = DCAF_ERROR_UNAUTHORIZED;
  dcaf_ticket_t *ticket;
  dcaf_dep_ticket_t *dep_ticket;
  abor_decoder_t *ticket_face = NULL;
  abor_decoder_t *abd = NULL, *cose_key;
  dcaf_time_t now;
  int remaining_ltm;
  dcaf_key_type key_type = DCAF_NONE;
  
  assert(result);
  *result = NULL;

  /* data must contain a valid access token which is a map or a
   * COSE_Encrypt0 structure.
   */
  if (maybe_cose(data, data_len)) {
    cose_obj_t *cose_obj = NULL;
    cose_result_t cose_res;
    /* TODO: plaintext could be allocated on the heap on demand but
     * must be released before this function is left. For now, we use
     * static memory which makes this function MT-unsafe. */
    static uint8_t plaintext[512];
    size_t plaintext_length = sizeof(plaintext);

    if (cose_parse(data, data_len, &cose_obj) != COSE_OK) {
      dcaf_log(DCAF_LOG_INFO, "cannot parse COSE object\n");
      goto finish;
    }

    /* Retrieve dcaf_context from session object and pass it as
     * argument to the get_am_key callback function. */
    cose_res = cose_decrypt(cose_obj, NULL, 0,
                            plaintext, &plaintext_length,
                            get_am_key,
                            get_dcaf_context_from_session(session));
    if (cose_res != COSE_OK) {
      dcaf_log(DCAF_LOG_INFO, "cannot decrypt COSE object\n");
      cose_obj_delete(cose_obj);
      goto finish;
    }
    cose_obj_delete(cose_obj);
    ticket_face = abor_decode_start(plaintext, plaintext_length);

    /* show ticket in debug output */
    if (ticket_face && (dcaf_get_log_level() >= DCAF_LOG_DEBUG)) {
      dcaf_log(DCAF_LOG_DEBUG, "found ticket face (decrypted):\n");
      dcaf_show_cbor(plaintext, plaintext_length);
    }
  } else {
    ticket_face = abor_decode_start(data, data_len);

    /* show ticket in debug output */
    if (ticket_face && (dcaf_get_log_level() >= DCAF_LOG_DEBUG)) {
      dcaf_log(DCAF_LOG_DEBUG, "found ticket face:\n");
      dcaf_show_cbor(data, data_len);
    }
  }

  /* FIXME: determine if ticket stems from an authorized SAM using */
  /* key derivation, SAM's signature or SAM's MAC  */

  if (!abor_check_type(ticket_face, ABOR_MAP)) {
    dcaf_log(DCAF_LOG_INFO, "cannot parse access ticket\n");
    goto finish;
  }

  /* process contents of ticket face */

  /* TODO: find out if the ticket was meant for me */

  abd = abor_mapget_int(ticket_face, DCAF_TICKET_SEQ);
  uint64_t seqnr;
  if (!abor_get_uint(abd, &seqnr)) {
    dcaf_log(DCAF_LOG_INFO, "sequence number not found or invalid\n");
    goto finish;
  }
  abor_decode_finish(abd);
  
  /* if we already have a ticket with this sequence number, */
  /* the new ticket is discarded */
  /* TODO: find ticket for certain AM (sequence numbers are unique per AM) */
  LL_FOREACH(dcaf_tickets,ticket) {
    if (seqnr == ticket->seq) {
	res = DCAF_OK;
	goto finish;
    }
  }

  /* search list of deprecated tickets for ticket with sequence
     number */
  LL_FOREACH(deprecated_tickets,dep_ticket) {
    if (seqnr == dep_ticket->seq) {
      res = DCAF_ERROR_INVALID_TICKET;
      goto finish;
    }
  }
  
  /* TODO: search revocation list for ticket with sequence number */
  
  /* if deprecated sequence number is specified, remove old ticket */
  abd = abor_mapget_int(ticket_face, DCAF_TICKET_DSEQ);
  uint64_t dseqnr;
  if (abor_get_uint(abd, &dseqnr)) {
    LL_FOREACH(dcaf_tickets,ticket) {
      if (dseqnr == ticket->seq){
	/* store ticket's seq and remaining lifetime in */
	/* list of deprecated tickets */
	dep_ticket = dcaf_new_dep_ticket(ticket->seq,ticket->ts, ticket->remaining_time);
	LL_PREPEND(deprecated_tickets,dep_ticket);
	/* remove old ticket from ticket list */
	dcaf_remove_ticket(ticket);
	break;
      }
    }
  }
  abor_decode_finish(abd);

  /* retrieve lifetime */
  abd = abor_mapget_int(ticket_face, DCAF_TICKET_EXPIRES_IN);
  uint64_t ltm_value;
  if (!abor_check_type(abd, ABOR_UINT) || !abor_get_uint(abd, &ltm_value)) {
    dcaf_log(DCAF_LOG_INFO, "no valid lifetime found\n");
    goto finish;
  }
  abor_decode_finish(abd);
  abd = NULL;

  /* Retrieve nonce/timestamp. Check available validity options. At
   * the end, remaining_ltm must have a positive value, otherwise, an
   * error is signaled. */
  remaining_ltm = -1;
  now = dcaf_gettime();

  if (DCAF_SERVER_VALIDITY_OPTION == 1) {
    abd = abor_mapget_int(ticket_face, DCAF_TICKET_IAT);
    if (abd) {
      uint64_t iat;
      if (!abor_get_uint(abd, &iat)) {
        dcaf_log(DCAF_LOG_INFO, "no valid iat found\n");
        goto finish;
      } else {
        remaining_ltm = ltm_value - (now - iat);
        /* check if lifetime is already exceeded  */
        if (!check_lifetime(remaining_ltm)) {
          goto finish;
        }
      }
      abor_decode_finish(abd);
    }
  }

  if (remaining_ltm < 0) {
    abd = abor_mapget_int(ticket_face, DCAF_TICKET_SNC);
    if (abor_check_type(abd, ABOR_BSTR)) {
      /* validity option 2 or 3 */
      int offset =
        dcaf_determine_offset_with_nonce(abor_get_bytes(abd),
                                         abor_get_sequence_length(abd));
      if (offset < 0) {
        dcaf_log(DCAF_LOG_INFO, "error calculating the offset\n");
        goto finish;
      } else {
        /* calculate the remaining lifetime */
        remaining_ltm = ltm_value - offset;
        /* check if lifetime is already exceeded  */
        if (!check_lifetime(remaining_ltm)) {
          goto finish;
        }
      }
    }
  }

  if (remaining_ltm < 0) {
    /* out of options */
    dcaf_log(DCAF_LOG_INFO, "no validity information found\n");
    goto finish;
  }
  abor_decode_finish(abd);
  
  /* retrieve cnf containg keying material information */
  abd = abor_mapget_int(ticket_face, DCAF_TICKET_CNF);
  if (!abd) {
    dcaf_log(DCAF_LOG_INFO, "no cnf found\n");
    goto finish;
  }

  *result = dcaf_new_ticket(key_type, seqnr, now, remaining_ltm);
  if (*result == NULL) {
    res = DCAF_ERROR_OUT_OF_MEMORY;
    dcaf_log(DCAF_LOG_WARNING, "cannot store new ticket (out of memory)\n");
    goto finish;
  }
  cose_key = get_cose_key(abd); /* CBOR object with cose key object */
  dcaf_parse_dcaf_key((*result)->key, cose_key);
  abor_decode_finish(cose_key);
  abor_decode_finish(abd);

  /* add permissions to ticket */
  abd = abor_mapget_int(ticket_face, DCAF_TICKET_SCOPE);
  /* TODO: handle scopes that are not AIF */
  if (abor_check_type(abd, ABOR_ARRAY)) {
    dcaf_aif_t *aif = NULL;
    res=dcaf_aif_parse(abd,&aif);
    if (res!=DCAF_OK) {
      goto finish;
    }
    (*result)->aif = aif;
  }
  /* no abor_decode_finish(abd) here as this is done below anyway */

  /* Set the session identifier in the ticket structure to the session
   * pointer. As this is just use as an opaque sequence of bytes, we
   * can just copy the value, regardless of the session's constness.
   */
  memcpy(&(*result)->session, &session, sizeof(void *));

  /* Set positive result */
  res = DCAF_OK;
   
 finish:
  abor_decode_finish(abd);
  abor_decode_finish(ticket_face);
  return res;
}
#endif /* DCAF_SERVER */

#if DCAF_SERVER
static size_t
dcaf_get_server_psk(const coap_session_t *session,
                    const uint8_t *identity, size_t identity_len,
                    uint8_t *psk, size_t max_psk_len) {
  dcaf_ticket_t *t = NULL;
  size_t result = 0;
#if DCAF_UTF8ENCODE_PSKIDENTITY
  size_t identity_buflen = identity_len;
  uint8_t *identity_buf = dcaf_alloc_type_len(DCAF_STRING, identity_len);
  if (!identity_buf ||
      !utf8_to_uint8(identity_buf, &identity_buflen, (const char *)identity, identity_len)) {
    dcaf_log(DCAF_LOG_WARNING, "Cannot decode ticket face. Parsing raw data.\n");
  } else {
    identity = identity_buf;
    identity_len = identity_buflen;
  }
#endif /* DCAF_UTF8ENCODE_PSKIDENTITY */
  if (dcaf_parse_ticket_face(session, identity, identity_len, &t) == DCAF_OK){
    /* got a new ticket; just store it and continue */
    dcaf_add_ticket(t);

    if (t &&  t->key && (t->key->length <=max_psk_len)) {
      /* TODO check if key is a psk and return 0 otherwise */
      memcpy(psk, t->key->data, t->key->length);
      /* return length of key */
      result = t->key->length;
      goto finish;
    }
  } else {
    dcaf_context_t *dcaf_context;

    dcaf_context = get_dcaf_context_from_session(session);
    assert(dcaf_context);
    if (dcaf_context) {
      /* TODO check if we want to pass &session->remote_addr as well.
       *      (keys would need to be added with peer addr set to make
       *      this work) */
      dcaf_key_t *key = dcaf_find_key(dcaf_context, NULL,
                                      identity, identity_len);

      if (key) {
        dcaf_log(DCAF_LOG_DEBUG, "found psk for %.*s\n",
                 (int)identity_len, identity);
        memcpy(psk, key->data, key->length);
        result = key->length;
        goto finish;
      }
    }
  }
 finish:
  dcaf_free_type(DCAF_STRING, identity_buf);
  return result;
}
#endif /* DCAF_SERVER */

dcaf_context_t *
dcaf_new_context(const dcaf_config_t *config) {
  dcaf_context_t *dcaf_context;
  coap_address_t addr;
  const char *addr_str = "::";

  dcaf_context = (dcaf_context_t *)dcaf_alloc_type(DCAF_CONTEXT);
  if (!dcaf_context) {
    dcaf_log(DCAF_LOG_EMERG, "cannot allocate context\n");
    goto error;
  }

  memset(dcaf_context, 0, sizeof(dcaf_context_t));

#ifndef RIOT_VERSION
  dcaf_context->coap_context = coap_new_context(NULL);
#else /* RIOT_VERSION */
  dcaf_context->coap_context = coap_context;
#endif /* RIOT_VERSION */
  if (dcaf_context->coap_context == NULL) {
    dcaf_log(DCAF_LOG_EMERG, "Cannot create new CoAP context.\n");
    goto error;
  }

  /* initialize PSK mode */
  coap_context_set_psk(dcaf_context->coap_context, NULL, NULL, 0);

#if DCAF_SERVER
  dcaf_context->coap_context->get_server_psk = dcaf_get_server_psk;
#endif /* DCAF_SERVER */
  coap_set_app_data(dcaf_context->coap_context, dcaf_context);

  if (config) {
    if (config->host) {
      addr_str = config->host;
    }

    /* Bind address for plaintext communication if coap_port was
     * configured. */
    if (config->coap_port &&
        (dcaf_set_coap_address((const unsigned char *)addr_str,
                               strlen(addr_str),
                               config->coap_port, &addr) == DCAF_OK)) {
      if (set_endpoint(dcaf_context, &addr, COAP_PROTO_UDP)) {
        unsigned char buf[INET6_ADDRSTRLEN + 8];

        if (coap_print_addr(&addr, buf, INET6_ADDRSTRLEN + 8)) {
          dcaf_log(DCAF_LOG_INFO, "listen on address %s (UDP)\n", buf);
        }
      }
    }

    /* Bind address for secure communication if coaps_port was
     * configured. */
    if (config->coaps_port &&
        (dcaf_set_coap_address((const unsigned char *)addr_str,
                               strlen(addr_str),
                               config->coaps_port, &addr) == DCAF_OK)) {
      if (set_endpoint(dcaf_context, &addr, COAP_PROTO_DTLS)) {
        unsigned char buf[INET6_ADDRSTRLEN + 8];

        if (coap_print_addr(&addr, buf, INET6_ADDRSTRLEN + 8)) {
          dcaf_log(DCAF_LOG_INFO, "listen on address %s (DTLS)\n", buf);
        }
      }
    }

    /* set am_uri from config->am_uri */
    if (config->am_uri) {
      dcaf_set_am_uri(dcaf_context,
                      (const unsigned char *)config->am_uri,
                      strlen(config->am_uri));
      if (dcaf_context->am_uri==NULL){
        dcaf_log(DCAF_LOG_CRIT, "cannot set AM URI %s. Expected schema://host[...]\n", config->am_uri);
      } else {
        dcaf_log(DCAF_LOG_INFO, "AM URI is %s\n", config->am_uri);
      }
    }
  }

  coap_register_option(dcaf_context->coap_context, COAP_OPTION_BLOCK2);
#if DCAF_CLIENT
  coap_register_response_handler(dcaf_context->coap_context,
                                 handle_coap_response);
#endif /* DCAF_CLIENT */

  return dcaf_context;
 error:
  dcaf_free_context(dcaf_context);
  return NULL;
}

void dcaf_free_context(dcaf_context_t *context) {
  if (context) {
    dcaf_free_type(DCAF_STRING, context->am_uri);
    coap_free_context(context->coap_context);
  }
  dcaf_free_type(DCAF_CONTEXT, context);
}

void
dcaf_set_app_data(dcaf_context_t *dcaf_context, void *app_data) {
  assert(dcaf_context);
  dcaf_context->app = app_data;
}

void *
dcaf_get_app_data(dcaf_context_t *dcaf_context) {
  assert(dcaf_context);
  return dcaf_context->app;
}

dcaf_context_t *
dcaf_get_dcaf_context(coap_context_t *coap_context) {
  return (dcaf_context_t *)coap_get_app_data(coap_context);
}

int
dcaf_set_am_uri(dcaf_context_t *context,
                const unsigned char *uri,
                size_t length) {
  assert(context);
  coap_free(context->am_uri);
  context->am_uri = coap_new_uri(uri, length);
  return context->am_uri &&
    (dcaf_set_coap_address(context->am_uri->host.s,
                           context->am_uri->host.length,
                           context->am_uri->port,
                           &context->am_address) == 0);
}

const coap_address_t *
dcaf_get_am_address(dcaf_context_t *context) {
  assert(context);
  return (context->am_uri != NULL) ? &context->am_address : NULL;
}

coap_context_t *
dcaf_get_coap_context(dcaf_context_t *context) {
  return context->coap_context;
}

static int
is_secure(const coap_session_t *session) {
  return (session != NULL) &&
    ((session->proto & COAP_PROTO_DTLS) != 0);
}
#if 0
coap_endpoint_t *
dcaf_select_interface(dcaf_context_t *context,
                      const coap_address_t *dst UNUSED,
                      int secure) {
  coap_endpoint_t *ep;

  LL_FOREACH(context->coap_context->endpoint, ep) {
    if (!secure || is_secure(ep)) {
      break;
    }
  }
  return ep;
}
#endif

static dcaf_check_scope_callback_t check_scope = NULL;

void dcaf_set_scope_check_function(dcaf_check_scope_callback_t func) {
  check_scope = func;
}

static bool
dcaf_default_check_scope(dcaf_scope_t type, void *perm, const coap_pdu_t *pdu) {
  switch (type) {
  default: return false;
  case DCAF_SCOPE_AIF: return dcaf_aif_allowed((const dcaf_aif_t *)perm, pdu);
  }
}

int
dcaf_is_authorized(const coap_session_t *session,
                   coap_pdu_t *pdu) {
  int result = 0;               /* not authorized by default */
  if (is_secure(session)) {
    dcaf_ticket_t *ticket;
    dcaf_check_scope_callback_t check =
      check_scope ? check_scope : dcaf_default_check_scope;
    
    /* retrieve ticket from session and check if it is still available. */
    ticket = dcaf_find_ticket(session);
    if (ticket) {
      /* check expiration time */
      dcaf_time_t now = dcaf_gettime();
      if ((ticket->ts+ticket->remaining_time)<=now) {
	/* ticket expired */
	return 0;
      }
      /* check method and uri */
      result = check(DCAF_SCOPE_AIF, ticket->aif, pdu);
      if (!result) {
        dcaf_log(DCAF_LOG_INFO, "access denied\n");
      }
    }
  }
  return result;
}

dcaf_nonce_t * nonces = NULL;

#if DCAF_SERVER
dcaf_result_t
dcaf_set_sam_information(const coap_session_t *session,
                         dcaf_mediatype_t mediatype,
                         coap_pdu_t *response) {
  /* We do not expect the SAM information to require more than 128
   * bytes. The size depends primarily on the length of the SAM URI.
   * Besides, only a few bytes for CBOR map keys and the validity
   * options are required. */
  static unsigned char buf[64];
  unsigned char cf[4];          /* the content format is encoded here. */
  abor_encoder_t *abc; /* CBOR encoder */
  bool ok;
  coap_tick_t now;
  dcaf_context_t *dcaf_context;

  dcaf_log(DCAF_LOG_DEBUG, "create SAM Information\n");
  coap_ticks(&now);
  assert(session != NULL);
  assert(session->context != NULL);
  assert(response != NULL);

  if (!session || !response) {
    return DCAF_ERROR_INTERNAL_ERROR;
  }
  dcaf_context = dcaf_get_dcaf_context(session->context);
  if (!dcaf_context) {
    dcaf_log(DCAF_LOG_DEBUG, "DCAF_ERROR_INTERNAL_ERROR\n");
    return DCAF_ERROR_INTERNAL_ERROR;
  }

  /* The DCAF unauthorized response is constructed only when a proper
   * SAM URI is set. */
  if (!dcaf_context->am_uri) {
    dcaf_log(DCAF_LOG_DEBUG, "no SAM URI\n");
    coap_set_response_code(response, COAP_RESPONSE_CODE_UNAUTHORIZED);
    return DCAF_OK;
  }

  if (!coap_add_option(response, COAP_OPTION_CONTENT_FORMAT,
                       coap_encode_var_safe(cf, sizeof(cf), mediatype),
                       cf)) {
    dcaf_log(DCAF_LOG_DEBUG, "DCAF_ERROR_BUFFER_TOO_SMALL\n");
    return DCAF_ERROR_BUFFER_TOO_SMALL;
  }

  /* generate sam information message */
  abc = abor_encode_start(buf, sizeof(buf));
  ok = abc && abor_write_map(abc, 2);

  /* Set SAM URI. The URI is stored as zero-terminated string right
   * after the coap_uri_t structure in the am_uri. */
  const char *uri = (const char *)dcaf_context->am_uri + sizeof(coap_uri_t);
  ok = ok && abor_write_int(abc, DCAF_REQ_SAM);
  ok = ok && abor_write_string(abc, uri);

  /* set validity information */
  if (DCAF_SERVER_VALIDITY_OPTION != 1) {
    dcaf_nonce_t *nonce;
    uint16_t validity_key = DCAF_REQ_SNC;
    /* create nonce */
    nonce = dcaf_new_nonce(DCAF_MAX_NONCE_SIZE);
    if (!nonce) {
      dcaf_log(DCAF_LOG_DEBUG, "DCAF_ERROR_INTERNAL_ERROR\n");
      return DCAF_ERROR_INTERNAL_ERROR;
    }
    /* store nonce */
    dcaf_prng(nonce->nonce, nonce->nonce_length);
    if (DCAF_SERVER_VALIDITY_OPTION == 2) {
      nonce->validity_type = 2;
      /* store timestamp */
      nonce->validity_value.dat = (dcaf_time_t)coap_ticks_to_rt(now);
    }
    else {
      nonce->validity_type=3;
      /* store timer */
      nonce->validity_value.timer=DCAF_MAX_SERVER_TIMEOUT;
    }

    ok = ok && abor_write_int(abc, validity_key);
    ok = ok && abor_write_bytes(abc, nonce->nonce, nonce->nonce_length);

    if (ok) {
      LL_PREPEND(nonces, nonce);
    } else {
      dcaf_free_type(DCAF_NONCE, nonce);
    }
  }

  if (ok) {
    size_t length;
    length = abor_encode_finish(abc);

    if (!coap_add_data(response, length, buf)) {
      dcaf_log(DCAF_LOG_DEBUG, "also too small\n");
      return DCAF_ERROR_BUFFER_TOO_SMALL;
    }
  } else {
    if (abc)
      abor_encode_finish(abc);
  }

  coap_set_response_code(response, COAP_RESPONSE_CODE_UNAUTHORIZED);
  return DCAF_OK;
}
#endif /* DCAF_SERVER */

dcaf_result_t
dcaf_set_error_response(const coap_session_t *session,
                        dcaf_result_t error,
                        coap_pdu_t *response) {
  unsigned char buf[4];
  (void)session;
  (void)error;

  /* TODO: describe error, provide correct result */
  coap_set_response_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
  coap_add_option(response,
                  COAP_OPTION_CONTENT_FORMAT,
                  coap_encode_var_safe(buf, sizeof(buf),
                                       COAP_MEDIATYPE_TEXT_PLAIN),
                  buf);
  coap_add_data(response, 20, (unsigned char *)"error");
  return DCAF_OK;
}





