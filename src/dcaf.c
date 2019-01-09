/*
 * dcaf.c -- libdcaf core
 *
 * Copyright (C) 2015-2018 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2018 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/state.h"
#include "dcaf/utlist.h"
#include "dcaf/dcaf_cbor.h"

#include "dcaf/aif.h"
#include "dcaf/cwt.h"

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

/* Returns true iff DCAF should be used. */
static bool
is_dcaf(int content_format) {
  return (content_format == -1)
    || (content_format == DCAF_MEDIATYPE_DCAF_CBOR);
}

/**
 * Utility function to extract a COSE_Key from @p obj skipping the
 * CBOR tag if present.  This function returns a pointer to the
 * cn_cbor structure representing the actual COSE_Key, or NULL on
 * error.
 */
static inline const cn_cbor *
get_cose_key(const cn_cbor *obj) {
  assert(obj);

  obj = dcaf_cbor_mapget_int(obj, CWT_CNF_COSE_KEY);

  if (obj && (obj->type == CN_CBOR_TAG)) {
    return (obj->v.uint == COSE_KEY) ? obj->first_child : NULL;
  } else {
    return obj;
  }
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

static size_t
make_ticket_request(const uint8_t *data, size_t data_len,
                    uint8_t *result, size_t max_result_len) {
  cn_cbor *req = dcaf_cbor_decode(data, data_len, NULL);
  cn_cbor *scope;
  char uri[] = "coaps://node1";
  size_t len;

  if (!req || (req->type != CN_CBOR_MAP)) {
    return 0;
  }

  dcaf_cbor_mapput_int(req, DCAF_TICKET_AUD,
                       dcaf_cbor_string_create(uri, NULL),
                       NULL);

  scope = dcaf_cbor_array_create(NULL);
  dcaf_cbor_array_append(scope,
                         dcaf_cbor_string_create("/restricted", NULL),
                         NULL);
  dcaf_cbor_array_append(scope, dcaf_cbor_int_create(5, NULL), NULL);

  dcaf_cbor_mapput_int(req, DCAF_TICKET_SCOPE, scope, NULL);

  len = dcaf_cbor_encoder_write(result, 0, max_result_len, req);
  dcaf_cbor_free(req);

  return len;
}

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

    len = make_ticket_request(data, data_len,
                              ticket_req, sizeof(ticket_req));
    if (len > 0) {
      /* FIXME: Set Content-Format to DCAF_MEDIATYPE_DCAF_CBOR */
      /* pass SAM response to AM */
      dcaf_log(DCAF_LOG_DEBUG, "pass DCAF Unauthorized response to AM\n");
      am_t = dcaf_send_request_uri(dcaf_context, COAP_REQUEST_POST,
                                   dcaf_context->am_uri,
                                   NULL /* optlist */,
                                   ticket_req, len,
                                   0);
      if (am_t) {
        t->state.act = DCAF_STATE_ACCESS_REQUEST;
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

static void
handle_ticket_transfer(dcaf_context_t *dcaf_context,
                       dcaf_transaction_t *t,
                       coap_pdu_t *received) {
  size_t content_len = 0;
  uint8_t *content = NULL;
  cn_cbor *cbor;
  cn_cbor *ticket_face, *client_information, *cnf;
  const cn_cbor *cose_key = NULL;
  dcaf_ticket_t *cinfo;
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

  /* A constrained application may parse on-demand, i.e. treat the
   * ticket_face as opaque. */
  cbor = dcaf_cbor_decode(content, content_len, NULL);
  if (!cbor) {
    dcaf_log(DCAF_LOG_ERR, "cannot parse ticket\n");
    return;
  }

  /* TODO: get key from cbor and use ticket face as psk for new
     session */
  ticket_face = dcaf_cbor_mapget_int(cbor, DCAF_TICKET_FACE);
  client_information = dcaf_cbor_mapget_int(cbor, DCAF_TICKET_CLIENTINFO);

  if (!ticket_face || (ticket_face->type != CN_CBOR_MAP)) {
    dcaf_log(DCAF_LOG_INFO, "invalid ticket face\n");
    goto finish;
  }
  if (!client_information) {
    dcaf_log(DCAF_LOG_ERR, "ticket has no client information\n");
    goto finish;
  }

  /* retrieve cnf containg keying material information */
  cnf = dcaf_cbor_mapget_int(client_information, DCAF_TICKET_CNF);
  if (!cnf) {
    dcaf_log(DCAF_LOG_INFO, "no cnf found\n");
    goto finish;
  }

  cinfo = dcaf_new_ticket(key_type, 0 /* FIXME: seq->v.uint */,
                          0 /* FIXME: now */,
                          1000 /* FIXME: remaining_ltm */);
  cose_key = get_cose_key(cnf); /* cn_cbor object with cose key object */
  if (!cose_key) {
    dcaf_log(DCAF_LOG_INFO, "no COSE_Key found\n");
    goto finish;
  }
  dcaf_parse_dcaf_key(cinfo->key, cose_key);
  dcaf_log(DCAF_LOG_DEBUG, "we have a key!\n");

  if (dcaf_check_transaction(dcaf_context, t->state.future)) {
    /* The future transaction can be completed with the access
     * ticket we have received. We need to create a coaps session
     * with the ticket face as identity and the contained key
     * as PSK.
     */
  }
 finish:
  dcaf_cbor_free(cbor);
}

static void
handle_coap_response(struct coap_context_t *coap_context,
                     coap_session_t *session,
                     coap_pdu_t *sent,
                     coap_pdu_t *received,
                     const coap_tid_t id) {
  dcaf_context_t *dcaf_context;
  dcaf_transaction_t *t;
  int deliver = 0;
  uint8_t code;

  (void)session;
  (void)sent;
  (void)id;

  dcaf_context = dcaf_get_dcaf_context(coap_context);
  assert(dcaf_context);

  t = dcaf_find_transaction(dcaf_context, session, received);
  if (!t) {
    dcaf_log(DCAF_LOG_ERR, "dropped response for unknown transaction\n");
    return;
  }

  /* Call response handler or error handler, respectively. If not set,
   * this is the initial transaction that will be handled manually. */
  code = coap_get_response_code(received);
  if (t->response_handler) {
    dcaf_log(DCAF_LOG_DEBUG, "invoke response handler\n");
    t->response_handler(dcaf_context, t, received);
    dcaf_delete_transaction(dcaf_context, t);
    return;
  }

  /* Reached only for responses that have no handler, i.e., the
   * default behavior. */

  if (!is_dcaf(coap_get_content_format(received))) {
    dcaf_log(DCAF_LOG_INFO, "received non-dcaf response\n");
    /* FIXME: application delivery */
    dcaf_delete_transaction(dcaf_context, t);
    return;
  }

  switch (t->state.act) {
  case DCAF_STATE_IDLE: {
    /* FIXME: check response code, handle DCAF SAM response
              deliver message in any other case */
    if (code == COAP_CODE_UNAUTHORIZED) {
      handle_unauthorized(dcaf_context, t, received);
    } else {           /* handle final response for transaction t */
      dcaf_log(DCAF_LOG_DEBUG, "received final response with code %u\n",
               code);
      return;
    }
    break;
  }
  case DCAF_STATE_ACCESS_REQUEST:
    /* Handle response to previous access request */

    if (COAP_RESPONSE_CLASS(code) == 2) {
      handle_ticket_transfer(dcaf_context, t, received);
      t->state.act = DCAF_STATE_AUTHORIZED;
      return;
    } else {                  /* access request failed */
      /* FIXME: signal error to application */
      dcaf_log(DCAF_LOG_CRIT, "access request failed\n");
      dcaf_delete_transaction(dcaf_context, t);
      return;
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
    return;
  }

  if (deliver && t->response_handler) {
    t->response_handler(dcaf_context, t, received);
  }
#if 0
  coap_pdu_t *pdu = NULL;
  coap_opt_t *block_opt;
  coap_opt_iterator_t opt_iter;
  unsigned char buf[4];
  dcaf_option_t *option;
  size_t len;
  unsigned char *databuf;
  coap_tid_t tid;

#ifndef NDEBUG
  if (DCAF_LOG_DEBUG <= coap_get_log_level()) {
    debug("** process incoming %d.%02d response:\n",
          (received->code >> 5), received->code & 0x1F);
    coap_show_pdu(received);
  }
#endif

  /* check if this is a response to our original request */
  if (!check_token(received)) {
    /* drop if this was just some message, or send RST in case of notification */
    if (!sent && (received->type == COAP_MESSAGE_CON ||
                  received->type == COAP_MESSAGE_NON))
      coap_send_rst(ctx, local_interface, remote, received);
    return;
  }

  if (received->type == COAP_MESSAGE_RST) {
    info("got RST\n");
    return;
  }

  /* output the received data, if any */
  if (COAP_RESPONSE_CLASS(received->code) == 2) {

    /* set obs timer if we have successfully subscribed a resource */
    if (sent && coap_check_option(received, COAP_OPTION_SUBSCRIPTION, &opt_iter)) {
      debug("observation relationship established, set timeout to %d\n", obs_seconds);
      set_timeout(&obs_wait, obs_seconds);
      observe = 1;
    }

    /* Got some data, check if block option is set. Behavior is undefined if
     * both, Block1 and Block2 are present. */
    block_opt = coap_check_option(received, COAP_OPTION_BLOCK2, &opt_iter);
    if (block_opt) { /* handle Block2 */
      unsigned short blktype = opt_iter.type;

      /* TODO: check if we are looking at the correct block number */
      if (coap_get_data(received, &len, &databuf))
        append_to_output(databuf, len);

      if(COAP_OPT_BLOCK_MORE(block_opt)) {
        /* more bit is set */
        debug("found the M bit, block size is %u, block nr. %u\n",
              COAP_OPT_BLOCK_SZX(block_opt),
              coap_opt_block_num(block_opt));

        /* create pdu with request for next block */
        pdu = coap_new_request(ctx, method, NULL, NULL, 0); /* first, create bare PDU w/o any option  */
        if (pdu) {
          /* add URI components from optlist */
          for (option = optlist; option; option = dcaf_optlist_get_next(option)) {
            switch (option->key) {
              case COAP_OPTION_URI_HOST :
              case COAP_OPTION_URI_PORT :
              case COAP_OPTION_URI_PATH :
              case COAP_OPTION_URI_QUERY :
                coap_add_option(pdu, option->key, option->size, option->data);
                break;
              default:
                ;     /* skip other options */
            }
          }

          /* finally add updated block option from response, clear M bit */
          /* blocknr = (blocknr & 0xfffffff7) + 0x10; */
          debug("query block %d\n", (coap_opt_block_num(block_opt) + 1));
          coap_add_option(pdu,
                          blktype,
                          coap_encode_var_bytes(buf,
                                 ((coap_opt_block_num(block_opt) + 1) << 4) |
                                  COAP_OPT_BLOCK_SZX(block_opt)), buf);

          if (pdu->type == COAP_MESSAGE_CON)
            tid = coap_send_confirmed(ctx, local_interface, remote, pdu);
          else
            tid = coap_send(ctx, local_interface, remote, pdu);

          if (tid == COAP_INVALID_TID) {
            debug("message_handler: error sending new request");
            coap_delete_pdu(pdu);
          } else {
            set_timeout(&max_wait, wait_seconds);
            if (pdu->type != COAP_MESSAGE_CON)
              coap_delete_pdu(pdu);
          }

          return;
        }
      }
    } else { /* no Block2 option */
      block_opt = coap_check_option(received, COAP_OPTION_BLOCK1, &opt_iter);

      if (block_opt) { /* handle Block1 */
        block.szx = COAP_OPT_BLOCK_SZX(block_opt);
        block.num = coap_opt_block_num(block_opt);

        debug("found Block1, block size is %u, block nr. %u\n",
        block.szx, block.num);

        if (payload.length <= (block.num+1) * (1 << (block.szx + 4))) {
          debug("upload ready\n");
          ready = 1;
          return;
        }

        /* create pdu with request for next block */
        pdu = coap_new_request(ctx, method, NULL, NULL, 0); /* first, create bare PDU w/o any option  */
        if (pdu) {

          /* add URI components from optlist */
          for (option = optlist; option; option = dcaf_optlist_get_next(option)) {
            switch (option->key) {
              case COAP_OPTION_URI_HOST :
              case COAP_OPTION_URI_PORT :
              case COAP_OPTION_URI_PATH :
              case COAP_OPTION_CONTENT_FORMAT :
              case COAP_OPTION_URI_QUERY :
                coap_add_option (pdu, option->key, option->size, option->data);
                break;
              default:
              ;     /* skip other options */
            }
          }

          /* finally add updated block option from response, clear M bit */
          /* blocknr = (blocknr & 0xfffffff7) + 0x10; */
          block.num++;
          block.m = ((block.num+1) * (1 << (block.szx + 4)) < payload.length);

          debug("send block %d\n", block.num);
          coap_add_option(pdu,
                          COAP_OPTION_BLOCK1,
                          coap_encode_var_bytes(buf,
                          (block.num << 4) | (block.m << 3) | block.szx), buf);

          coap_add_block(pdu,
                         payload.length,
                         payload.s,
                         block.num,
                         block.szx);
          coap_show_pdu(pdu);
          if (pdu->type == COAP_MESSAGE_CON)
            tid = coap_send_confirmed(ctx, local_interface, remote, pdu);
          else
            tid = coap_send(ctx, local_interface, remote, pdu);

          if (tid == COAP_INVALID_TID) {
            debug("message_handler: error sending new request");
            coap_delete_pdu(pdu);
          } else {
            set_timeout(&max_wait, wait_seconds);
            if (pdu->type != COAP_MESSAGE_CON)
              coap_delete_pdu(pdu);
          }

          return;
        }
      } else {
        /* There is no block option set, just read the data and we are done. */
        if (coap_get_data(received, &len, &databuf))
        append_to_output(databuf, len);
      }
    }
  } else {      /* no 2.05 */

    /* check if an error was signaled and output payload if so */
    if (COAP_RESPONSE_CLASS(received->code) >= 4) {
      fprintf(stderr, "%d.%02d",
              (received->code >> 5), received->code & 0x1F);
      if (coap_get_data(received, &len, &databuf)) {
        fprintf(stderr, " ");
        while(len--)
        fprintf(stderr, "%c", *databuf++);
      }
      fprintf(stderr, "\n");
    }

  }

  /* finally send new request, if needed */
  if (pdu && coap_send(ctx, local_interface, remote, pdu) == COAP_INVALID_TID) {
    debug("message_handler: error sending response");
  }
  coap_delete_pdu(pdu);

  /* our job is done, we can exit at any time */
  ready = coap_check_option(received, COAP_OPTION_SUBSCRIPTION, &opt_iter) == NULL;
#endif
}

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
    if ((ticket->ts+ticket->remaining_time)>now) {
      dcaf_remove_ticket(ticket);
    }
  }
  /* search deprecated tickets for expired tickets */
  LL_FOREACH_SAFE(deprecated_tickets, dep_ticket,tempp) {
    if ((dep_ticket->ts+dep_ticket->remaining_time)>now) {
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
dcaf_find_ticket(const uint8_t *kid, size_t kid_length) {
  dcaf_ticket_t *ticket = NULL;
  /* fixme: kid is not necessarily unique. better search with seq */
  /* maybe search with kid and am */
  LL_FOREACH(dcaf_tickets,ticket) {
    if ((kid_length == ticket->key->kid_length)
	&& (memcmp(kid, ticket->key->kid, ticket->key->kid_length) == 0)) {
      return ticket;
    }
  }
  return NULL;
}

dcaf_ticket_t *
dcaf_new_ticket(const dcaf_key_type key_type,
		const unsigned long seq, const dcaf_time_t ts,
		const uint remaining_time) {

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
		    const uint remaining_time) {
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

/* helper function to log cn-cbor parse errors */
static inline void
log_parse_error(const cn_cbor_errback err) {
  dcaf_log(DCAF_LOG_ERR, "parse error %d at pos %d\n", err.err, err.pos);
}

void
dcaf_parse_dcaf_key(dcaf_key_t *key, const cn_cbor* cose_key) {
  if (cose_key && key) {
    cn_cbor * obj;
    /* set kid */
    obj = dcaf_cbor_mapget_int(cose_key,COSE_KEY_KID);
    if (obj && (obj->type == CN_CBOR_BYTES) && (obj->length <= DCAF_MAX_KID_SIZE)) {
      memcpy(key->kid,obj->v.bytes,obj->length);
      key->kid_length = obj->length;
    }
    obj = dcaf_cbor_mapget_int(cose_key,COSE_KEY_ALG);
    if (obj && (obj->type == CN_CBOR_INT)) {
      switch (obj->v.sint) {
      case COSE_AES_CCM_64_64_128:
	key->type=DCAF_AES_128;
	break;
	/* TODO: other cases */
      default:
	;
      }
    }
    /* set key */
    obj = dcaf_cbor_mapget_int(cose_key,COSE_KEY_K);
    if (obj && (obj->type == CN_CBOR_BYTES) && (obj->length <= DCAF_MAX_KEY_SIZE)) {
      memcpy(key->data,obj->v.bytes,obj->length);
      key->length = obj->length;
    }
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

static inline int
maybe_cose(const uint8_t *data, size_t length) {
  if (data && (length > 0)) {
    int tag = get_cbor_tag(data, length);
    switch (tag) {
    case -1:                    /* not tagged, look for array */
      return cbor_major_type(data[0]) == CBOR_MAJOR_TYPE_ARRAY;
    case COSE_ENCRYPT0: /* for now, only COSE_Encrypt0 is recognized */
      return (length > 1) && (cbor_major_type(data[1]) == CBOR_MAJOR_TYPE_ARRAY);
    default:
      ;
    }
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

dcaf_result_t
dcaf_parse_ticket_face(const coap_session_t *session,
                  const uint8_t *data, size_t data_len,
                  dcaf_ticket_t **result) {
  dcaf_result_t res = DCAF_ERROR_UNAUTHORIZED;
  cn_cbor *bstr = NULL;
  cn_cbor *ticket_face = NULL;
  dcaf_ticket_t *ticket;
  dcaf_dep_ticket_t *dep_ticket;
  const cn_cbor *cnf, *snc, *iat, *ltm, *scope;
  const cn_cbor *seq, *dseq, *cose_key;
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

    if (cose_parse(bstr->v.bytes, bstr->length, &cose_obj) != COSE_OK) {
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
    ticket_face = dcaf_cbor_decode(plaintext, plaintext_length, NULL);
  } else {
    ticket_face = dcaf_cbor_decode(data, data_len, NULL);
  }

  /* FIXME: determine if ticket stems from an authorized SAM using */
  /* key derivation, SAM's signature or SAM's MAC  */

  if (!ticket_face || (ticket_face->type != CN_CBOR_MAP)) {
    dcaf_log(DCAF_LOG_INFO, "cannot parse access ticket\n");
    goto finish;
  }

  /* process contents of ticket face */

  /* TODO: find out if the ticket was meant for me */

  seq = dcaf_cbor_mapget_int(ticket_face, DCAF_TICKET_SEQ);
  if (!seq) {
    dcaf_log(DCAF_LOG_INFO, "no seqence number found\n");
    goto finish;
  }
  if (seq->type != CN_CBOR_UINT) {
    dcaf_log(DCAF_LOG_INFO, "sequence number has invalid format\n");
    goto finish;
  }
  
  /* if we already have a ticket with this sequence number, */
  /* the new ticket is discarded */
  /* TODO: find ticket for certain AM (sequence numbers are unique per AM) */
  LL_FOREACH(dcaf_tickets,ticket) {
    if (seq->v.uint == ticket->seq) {
	res = DCAF_OK;
	goto finish;
    }
  }

  /* search list of deprecated tickets for ticket with sequence
     number */
  LL_FOREACH(deprecated_tickets,dep_ticket) {
    if (seq->v.uint == ticket->seq) {
      res = DCAF_ERROR_INVALID_TICKET;
      goto finish;
    }
  }
  
  /* TODO: search revocation list for ticket with sequence number */
  
  /* if deprecated sequence number is specified, remove old ticket */
  dseq = dcaf_cbor_mapget_int(ticket_face,DCAF_TICKET_DSEQ);
  if (dseq) {
    LL_FOREACH(dcaf_tickets,ticket) {
      if (dseq->v.uint == ticket->seq){
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

  /* retrieve lifetime */
  ltm = dcaf_cbor_mapget_int(ticket_face, DCAF_TICKET_EXPIRES_IN);
  if (!ltm || !(ltm->type == CN_CBOR_UINT)) {    
    dcaf_log(DCAF_LOG_INFO, "no valid lifetime found\n");
    goto finish;
  }

  /* retrieve nonce/timestamp */
  snc = dcaf_cbor_mapget_int(ticket_face, DCAF_TICKET_SNC);
  iat = dcaf_cbor_mapget_int(ticket_face, DCAF_TICKET_IAT);
  now = dcaf_gettime();
  if ((DCAF_SERVER_VALIDITY_OPTION == 1) && iat) {
    /* validity option 1 */
    if (iat->type!=CN_CBOR_UINT) {
      dcaf_log(DCAF_LOG_INFO, "no valid iat found\n");
      goto finish;
    }
    remaining_ltm = (ltm->v.uint - (now - iat->v.uint));
    if (remaining_ltm <= 0) {
      /* lifetime already exceeded  */
      dcaf_log(DCAF_LOG_INFO, "ticket lifetime exceeded\n");
      /* FIXME: different DCAF error code? */
      goto finish;
    }
  }
  else if (snc && (snc->type == CN_CBOR_BYTES)) {
    /* validity option 2 or 3 */
    int offset;
    offset = dcaf_determine_offset_with_nonce(snc->v.bytes, snc->length);
    if (offset < 0) {
      dcaf_log(DCAF_LOG_INFO, "error calculating the offset\n");
      goto finish;
    }
    else {
      /* calculate the remaining lifetime */
      remaining_ltm = ltm->v.uint - offset;
      if (remaining_ltm<=0) {
	dcaf_log(DCAF_LOG_INFO, "ticket lifetime already exceeded\n");
	goto finish;
      }
    }
  }
  else {
    dcaf_log(DCAF_LOG_INFO, "no validity information found\n");
    goto finish;
  }
  
  /* retrieve cnf containg keying material information */
  cnf = dcaf_cbor_mapget_int(ticket_face, DCAF_TICKET_CNF);
  if (!cnf) {
    dcaf_log(DCAF_LOG_INFO, "no cnf found\n");
    goto finish;
  }

  *result = dcaf_new_ticket(key_type,
                            seq->v.uint,
			    now, remaining_ltm);
  cose_key = get_cose_key(cnf); /* cn_cbor object with cose key object */
  dcaf_parse_dcaf_key((*result)->key, cose_key);

  /* add permissions to ticket */
  scope = dcaf_cbor_mapget_int(ticket_face, DCAF_TICKET_SCOPE);
  /* TODO: handle scopes that are not AIF */
  if (scope && scope->type==CN_CBOR_ARRAY) {
    dcaf_aif_t *aif;
    res=dcaf_aif_parse_string(scope,&aif);
    if (res!=DCAF_OK) {
      goto finish;
    }
    ticket->aif = aif;
  }

  res = DCAF_OK;
   
 finish:
  dcaf_cbor_free(bstr);
  dcaf_cbor_free(ticket_face);
  return res;
}

static size_t
dcaf_get_server_psk(const coap_session_t *session,
                    const uint8_t *identity, size_t identity_len,
                    uint8_t *psk, size_t max_psk_len) {
  dcaf_ticket_t *t = NULL;
  dcaf_log(DCAF_LOG_DEBUG, "dcaf_get_server_psk() called\n");
  if (dcaf_parse_ticket_face(session, identity, identity_len, &t) == DCAF_OK){
    /* got a new ticket; just store it and continue */
    dcaf_add_ticket(t);

    if (t &&  t->key && (t->key->length <=max_psk_len)) {
      /* TODO check if key is a psk and return 0 otherwise */
      memcpy(psk, t->key->data, t->key->length);
      /* return length of key */
      return t->key->length;
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
        return key->length;
      }
    }
  }
  return 0;
}

static size_t
dcaf_get_client_psk(const coap_session_t *session,
                    const uint8_t *hint, size_t hint_len,
                    uint8_t *identity, size_t *identity_len,
                    size_t max_identity_len,
                    uint8_t *psk, size_t max_psk_len) {
  dcaf_context_t *dcaf_context;
  (void)hint;
  (void)hint_len;
  dcaf_log(DCAF_LOG_DEBUG, "dcaf_get_client_psk() called\n");

  dcaf_context = get_dcaf_context_from_session(session);
  assert(dcaf_context);
  if (dcaf_context) {
    dcaf_key_t *k;
    /* TODO: use hint as search criteria? */
    k = dcaf_find_key(dcaf_context, &session->remote_addr, NULL, 0);

    if (!k) {
      dcaf_log(DCAF_LOG_ERR, "cannot find credentials\n");
      return 0;
    }
    if (k->kid_length > 0) {
      if (max_identity_len < k->kid_length) {
        dcaf_log(DCAF_LOG_ERR, "cannot store identity (buffer too small)\n");
        return 0;
      }

      memset(identity, 0, max_identity_len);
      memcpy(identity, k->kid, k->kid_length);
      *identity_len = k->kid_length;
      dcaf_log(DCAF_LOG_DEBUG, "set identity to '%.*s' (%zu bytes)\n", (int)*identity_len, identity, *identity_len);
    }
    if (k->length > 0) {
      if (max_psk_len < k->length) {
        dcaf_log(DCAF_LOG_ERR, "cannot store PSK (buffer too small)\n");
        return 0;
      }
      memset(psk, 0, max_psk_len);
      memcpy(psk, k->data, k->length);
      dcaf_log(DCAF_LOG_DEBUG, "set psk to '%.*s' (%zu bytes)\n", (int)k->length, k->data, k->length);
      return k->length;
    }
  }

  return 0;
}

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

  dcaf_context->coap_context = coap_new_context(NULL);
  if (dcaf_context->coap_context == NULL) {
    dcaf_log(DCAF_LOG_EMERG, "Cannot create new CoAP context.\n");
    goto error;
  }

  /* initialize PKS mode */
  coap_context_set_psk(dcaf_context->coap_context, NULL, NULL, 0);

  dcaf_context->coap_context->get_client_psk = dcaf_get_client_psk;
  dcaf_context->coap_context->get_server_psk = dcaf_get_server_psk;
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
  coap_register_response_handler(dcaf_context->coap_context,
                                 handle_coap_response);

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
    
    /* FIXME dcaf_find_ticket expects the key id, not the psk identity */
    ticket = dcaf_find_ticket(session->psk_identity, session->psk_identity_len);
    if (ticket) {
      /* check expiration time */
      dcaf_time_t now = dcaf_gettime();
      if ((ticket->ts+ticket->remaining_time)>=now) {
	/* ticket expired */
	return 0;
      }
      /* check method and uri */
      result = check(DCAF_SCOPE_AIF, ticket->aif, pdu);
      if (!result) {
        dcaf_log(DCAF_LOG_INFO, "access denied\n");
      }
    }
    /* TODO cases where the ticket is transported in the psk_identity */
    dcaf_log(DCAF_LOG_DEBUG, "PSK identity is '%.*s':\n",
             (int)session->psk_identity_len, (char *)session->psk_identity);
  }
  return result;
}

dcaf_nonce_t * nonces = NULL;

dcaf_result_t
dcaf_set_sam_information(const coap_session_t *session,
                         dcaf_mediatype_t mediatype,
                         coap_pdu_t *response) {
  unsigned char buf[100];
  size_t length;
  coap_tick_t now;
  dcaf_context_t *dcaf_context;
  uint16_t sam_key = DCAF_TICKET_ISS, validity_key = DCAF_TICKET_DAT;
  dcaf_nonce_t *nonce;

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
    coap_set_response_code(response, COAP_CODE_UNAUTHORIZED);
    return DCAF_OK;
  }

  if (!coap_add_option(response, COAP_OPTION_CONTENT_FORMAT,
                       coap_encode_var_safe(buf, sizeof(buf), mediatype),
                       buf)) {
    dcaf_log(DCAF_LOG_DEBUG, "DCAF_ERROR_BUFFER_TOO_SMALL\n");
    return DCAF_ERROR_BUFFER_TOO_SMALL;
  }

  /* generate sam information message */
  cn_cbor *map = dcaf_cbor_map_create(NULL);
  const char *uri = (const char *)dcaf_context->am_uri + sizeof(coap_uri_t);

  /* TODO: fix ACE_ASINFO_AS and ACE_ASINFO_NONCE */
  /* if (!is_dcaf(mediatype)) { */
  /*   sam_key = ACE_ASINFO_AS; */
  /*   nonce_key = ACE_ASINFO_NONCE; */
  /* } */

  dcaf_log(DCAF_LOG_DEBUG, "CBOR...\n");
  /* set SAM URI */
  dcaf_cbor_mapput_int(map, sam_key,
                       dcaf_cbor_string_create(uri, NULL),
                       NULL);

  if (DCAF_SERVER_VALIDITY_OPTION == 1) {
    /* set timestamp */
    dcaf_cbor_mapput_int(map, validity_key,
                         dcaf_cbor_int_create(coap_ticks_to_rt(now), NULL),
                         NULL);
  }
  else {
    validity_key = DCAF_TICKET_SNC;
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
    LL_PREPEND(nonces, nonce);
  }
  
#ifdef DCAF_EXTENSIONS
  if (is_dcaf(mediatype)) {
    cn_cbor *accept = dcaf_cbor_array_create(NULL);
    dcaf_cbor_array_append(accept,
                           dcaf_cbor_int_create(DCAF_MEDIATYPE_DCAF_CBOR,
                                                NULL),
                           NULL);
  dcaf_cbor_mapput_int(map, DCAF_TYPE_A, accept, NULL);
  }
#endif /* DCAF_EXTENSIONS */

  length = dcaf_cbor_encoder_write(buf, 0, sizeof(buf), map);
  dcaf_cbor_free(map);

  if (!coap_add_data(response, length, buf)) {
    dcaf_log(DCAF_LOG_DEBUG, "also too small\n");
    return DCAF_ERROR_BUFFER_TOO_SMALL;
  }

  coap_set_response_code(response, COAP_CODE_UNAUTHORIZED);
  return DCAF_OK;
}

dcaf_result_t
dcaf_set_error_response(const coap_session_t *session,
                        dcaf_result_t error,
                        coap_pdu_t *response) {
  unsigned char buf[4];
  (void)session;
  (void)error;

  /* TODO: describe error, provide correct result */
  coap_set_response_code(response, COAP_CODE_BAD_REQUEST);
  coap_add_option(response,
                  COAP_OPTION_CONTENT_FORMAT,
                  coap_encode_var_safe(buf, sizeof(buf),
                                       COAP_MEDIATYPE_TEXT_PLAIN),
                  buf);
  coap_add_data(response, 20, (unsigned char *)"error");
  return DCAF_OK;
}





