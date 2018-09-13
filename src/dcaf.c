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

#include <cn-cbor/cn-cbor.h>

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/state.h"
#include "dcaf/utlist.h"

#include "dcaf/aif.h"
#include "dcaf/cwt.h"

#ifndef RIOT_VERSION
static inline uint8_t
coap_get_token_len(coap_pdu_t *p) {
  return p->token_length;
}
#endif

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

#ifdef RIOT_VERSION
struct coap_session_t {
  coap_address_t remote_addr;
};
#endif

static void
handle_coap_response(struct coap_context_t *coap_context,
                     coap_session_t *session,
                     coap_pdu_t *sent,
                     coap_pdu_t *received,
                     const coap_tid_t id) {
  dcaf_context_t *dcaf_context;
  dcaf_transaction_t *t;
  int deliver = 0;

  (void)session;
  (void)sent;
  (void)id;

  dcaf_context = dcaf_get_dcaf_context(coap_context);
  assert(dcaf_context);

  t = dcaf_find_transaction(dcaf_context, &session->remote_addr, received);
  if (!t) {
    dcaf_log(DCAF_LOG_ERR, "dropped response for unknown transaction\n");
    return;
  }

#if 0
  switch (t->state) {
  case DCAF_STATE_IDLE: {
    /* FIXME: check response code, handle DCAF SAM response
              deliver message in any other case */
    deliver = 1;
    break;
  }
  case DCAF_STATE_ACCESS_REQUEST:
    /* fall through */
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
#endif

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

static inline uint16_t
coap_port(const dcaf_config_t *config) {
  return (config && config->coap_port) ?
    config->coap_port : COAP_DEFAULT_PORT;
}

static inline uint16_t
coaps_port(const dcaf_config_t *config) {
  return (config && config->coaps_port) ?
    config->coaps_port : COAPS_DEFAULT_PORT;
}

static int
set_endpoint(const dcaf_context_t *dcaf_context,
             const coap_address_t *addr,
             coap_proto_t proto) {
#ifdef RIOT_VERSION
  (void)dcaf_context;
  (void)addr;
  (void)proto;
  return 0;  /* FIXME: RIOT */
#else
  return coap_new_endpoint(dcaf_context->coap_context, addr, proto) != NULL;
#endif
}

dcaf_ticket_t *dcaf_tickets = NULL;
dcaf_dep_ticket_t *deprecated_tickets = NULL;

static dcaf_ticket_t *
dcaf_find_ticket(const uint8_t *kid, size_t kid_length) {
  dcaf_ticket_t *ticket = NULL;
  LL_FOREACH(dcaf_tickets,ticket) {
    /*
    if ((kid_length == ticket->kid_length)
    && (memcmp(kid, ticket->kid, ticket->kid_length) == 0)) { */
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
    obj = cn_cbor_mapget_int(cose_key,COSE_KEY_KID);
    if (obj && (obj->type == CN_CBOR_BYTES) && (obj->length <= DCAF_MAX_KID_SIZE)) {
      memcpy(key->kid,obj->v.bytes,obj->length);
      key->kid_length = obj->length;
    }
    obj = cn_cbor_mapget_int(cose_key,COSE_KEY_ALG);
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
    obj = cn_cbor_mapget_int(cose_key,COSE_KEY_K);
    if (obj && (obj->type == CN_CBOR_BYTES) && (obj->length <= DCAF_MAX_KEY_SIZE)) {
      memcpy(key->data,obj->v.bytes,obj->length);
      key->length = obj->length;
    }
  }
}

static inline const cn_cbor *
get_cose_key(const cn_cbor *obj) {
  assert(obj);

  obj = cn_cbor_mapget_int(obj, CWT_CNF_COSE_KEY);

  if (obj && (obj->type == CN_CBOR_TAG)) {
    return (obj->v.uint == COSE_KEY) ? obj->first_child : NULL;
  } else {
    return obj;
  }
}

dcaf_time_t dcaf_gettime(void) {
  /* TODO: implement correct function */
  return time(0);
}

dcaf_nonce_t *dcaf_nonces = NULL;

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

dcaf_result_t
dcaf_parse_ticket(const coap_session_t *session,
                  const uint8_t *data, size_t data_len,
                  dcaf_ticket_t **result) {
  dcaf_result_t res = DCAF_ERROR_BAD_REQUEST;
  cn_cbor *bstr = NULL;
  cn_cbor *ticket_face = NULL;
  dcaf_ticket_t *ticket;
  dcaf_dep_ticket_t *dep_ticket;
  const cn_cbor *cnf, *snc, *iat, *ltm;
  const cn_cbor *seq, *dseq, *cose_key;
  cn_cbor_errback errp;
  dcaf_time_t now;
  int remaining_ltm;
  dcaf_key_type key_type = DCAF_NONE;
  
  (void)session;
  assert(result);
  *result = NULL;

  /* data must contain a valid access token which is a map that was
   * serialized as a CBOR byte string.
   */
  bstr = cn_cbor_decode(data, data_len, &errp);
  if (!bstr || (bstr->type != CN_CBOR_BYTES)) {
    dcaf_log(DCAF_LOG_INFO, "cannot parse access ticket\n");
    goto finish;
  }

  /* TODO: find out if the ticket was meant for me */

  /* FIXME: decrypt data first */
  ticket_face = cn_cbor_decode(bstr->v.bytes, bstr->length, NULL);
  if (!ticket_face || (ticket_face->type != CN_CBOR_MAP)) {
    dcaf_log(DCAF_LOG_INFO, "cannot parse access ticket\n");
    goto finish;
  }

  seq = cn_cbor_mapget_int(ticket_face, DCAF_TICKET_SEQ);
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
  dseq = cn_cbor_mapget_int(ticket_face,DCAF_TICKET_DSEQ);
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
  ltm = cn_cbor_mapget_int(ticket_face, DCAF_TICKET_EXPIRES_IN);
  if (!ltm || !(ltm->type == CN_CBOR_UINT)) {    
    dcaf_log(DCAF_LOG_INFO, "no valid lifetime found\n");
    goto finish;
  }

  /* retrieve nonce/timestamp */
  snc = cn_cbor_mapget_int(ticket_face, DCAF_TICKET_SNC);
  iat = cn_cbor_mapget_int(ticket_face, DCAF_TICKET_IAT);
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
  
  /* retrieve cnf claim to get kid and verifier */
  cnf = cn_cbor_mapget_int(ticket_face, DCAF_TICKET_CNF);
  if (!cnf) {
    dcaf_log(DCAF_LOG_INFO, "no cnf found\n");
    goto finish;
  }

  *result = dcaf_new_ticket(key_type,
                            seq->v.uint,
			    now, remaining_ltm);
  cose_key = get_cose_key(cnf); /* cn_cbor object with cose key object */
  dcaf_parse_dcaf_key((*result)->key, cose_key);

  /* TODO: add actual permissions to ticket */
  /* TODO: add ticket to ticket list */

  res = DCAF_OK;
   
 finish:
  cn_cbor_free(bstr);
  cn_cbor_free(ticket_face);
  return res;
}

static size_t
dcaf_get_server_psk(const coap_session_t *session,
                    const uint8_t *identity, size_t identity_len,
                    uint8_t *psk, size_t max_psk_len) {
  dcaf_ticket_t *t = dcaf_find_ticket(identity, identity_len);
  if (!t) { /* no ticket found, try to create new if possible */
    dcaf_log(DCAF_LOG_DEBUG, "no ticket found, checking if psk_identity contains an access token\n");
    if (dcaf_parse_ticket(session, identity, identity_len, &t) == DCAF_OK) {
      /* got a new ticket; just store it and continue */
      dcaf_add_ticket(t);
    }
  }

  if (t &&  t->key && (t->key->length <=max_psk_len)) {
    memcpy(psk, t->key->data, t->key->length);
    /* return length of key */
    return t->key->length;
  }
  /* if (t && t->verifier && (t->verifier_length <= max_psk_len)) { */
  /*   memcpy(psk, t->verifier, t->verifier_length); */
  /*   return t->verifier_length; */
  /* } */
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

#ifndef RIOT_VERSION
  dcaf_context->coap_context = coap_new_context(NULL);
  if (dcaf_context->coap_context == NULL) {
    dcaf_log(DCAF_LOG_EMERG, "Cannot create new CoAP context.\n");
    goto error;
  }

  static uint8_t key[] = "secretPSK";
  size_t key_len = sizeof(key) - 1;
  coap_context_set_psk(dcaf_context->coap_context, "CoAP", key, key_len);

  dcaf_context->coap_context->get_server_psk = dcaf_get_server_psk;
  coap_set_app_data(dcaf_context->coap_context, dcaf_context);
#endif /* RIOT_VERSION */

  if (config && config->host) {
    addr_str = config->host;
  }

  if (dcaf_set_coap_address((const unsigned char *)addr_str, strlen(addr_str),
                            coap_port(config), &addr) == DCAF_OK) {
    if (set_endpoint(dcaf_context, &addr, COAP_PROTO_UDP)) {
#ifndef RIOT_VERSION
      unsigned char buf[INET6_ADDRSTRLEN + 8];

      if (coap_print_addr(&addr, buf, INET6_ADDRSTRLEN + 8)) {
        dcaf_log(DCAF_LOG_INFO, "listen on address %s (UDP)\n", buf);
      }
#endif /* RIOT_VERSION */
    }
  }

  if (dcaf_set_coap_address((const unsigned char *)addr_str, strlen(addr_str),
                            coaps_port(config), &addr) == DCAF_OK) {
    if (set_endpoint(dcaf_context, &addr, COAP_PROTO_DTLS)) {
#ifndef RIOT_VERSION
      unsigned char buf[INET6_ADDRSTRLEN + 8];

      if (coap_print_addr(&addr, buf, INET6_ADDRSTRLEN + 8)) {
        dcaf_log(DCAF_LOG_INFO, "listen on address %s (DTLS)\n", buf);
      }
#endif /* RIOT_VERSION */
    }
  }

  /* set am_uri from config->am_uri */
  if (config && config->am_uri) {
    dcaf_set_am_uri(dcaf_context,
                    (const unsigned char *)config->am_uri,
                    strlen(config->am_uri));
  }

#ifndef RIOT_VERSION
  coap_register_option(dcaf_context->coap_context, COAP_OPTION_BLOCK2);
  coap_register_response_handler(dcaf_context->coap_context,
                                 handle_coap_response);
#endif /* RIOT_VERSION */

  return dcaf_context;
 error:
  dcaf_free_context(dcaf_context);
  return NULL;
}

void dcaf_free_context(dcaf_context_t *context) {
  if (context) {
    dcaf_free_type(DCAF_STRING, context->am_uri);
#ifndef RIOT_VERSION
    coap_free_context(context->coap_context);
#endif /* RIOT_VERSION */
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
#ifdef RIOT_VERSION
  (void)coap_context;
  return NULL; /* FIXME: RIOT */
#else
  return (dcaf_context_t *)coap_get_app_data(coap_context);
#endif /* RIOT_VERSION */
}

int
dcaf_set_am_uri(dcaf_context_t *context,
                const unsigned char *uri,
                size_t length) {
  assert(context);
#ifdef RIOT_VERSION
  (void)uri;
  (void)length;
  /* FIXME: RIOT */
  const unsigned char host[] = "sam.example.com";
  const size_t host_length = sizeof(host) - 1;
  const uint16_t port = 7744;
  return dcaf_set_coap_address(host, host_length, port,
                               &context->am_address) == 0;
#else
  coap_free(context->am_uri);
  context->am_uri = coap_new_uri(uri, length);

  return context->am_uri &&
    (dcaf_set_coap_address(context->am_uri->host.s,
                           context->am_uri->host.length,
                           context->am_uri->port,
                           &context->am_address) == 0);
#endif /* RIOT_VERSION */
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
#ifdef RIOT_VERSION
  /* FIXME: RIOT */
  return (session != NULL);
#else
  return (session != NULL) &&
    ((session->proto & COAP_PROTO_DTLS) != 0);
#endif /* RIOT_VERSION */
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

int
dcaf_is_authorized(const coap_session_t *session,
                   coap_pdu_t *pdu) {
  if (is_secure(session)) {
    /* FIXME: retrieve and check ticket */
    dcaf_ticket_t *ticket;
    ticket = dcaf_find_ticket(session->psk_identity, session->psk_identity_len);
    if (ticket) {
      /* check expiration time */
      /* check scope type */
      /* check method and uri */
    }
#ifndef RIOT_VERSION
    dcaf_log(DCAF_LOG_DEBUG, "PSK identity is '%.*s':\n",
             (int)session->psk_identity_len, (char *)session->psk_identity);
#endif /* RIOT_VERSION */
    return pdu != NULL;
  }
  return 0;
}


dcaf_result_t
dcaf_set_sam_information(const coap_session_t *session,
                         dcaf_mediatype_t mediatype,
                         coap_pdu_t *response) {
  unsigned char buf[100];
  size_t length;
  coap_tick_t now;
  dcaf_context_t *dcaf_context;
  uint16_t sam_key = DCAF_TYPE_SAM, nonce_key = DCAF_TYPE_NONCE;

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
    response->code = COAP_RESPONSE_CODE(401);
    return DCAF_OK;
  }

  if (!coap_add_option(response, COAP_OPTION_CONTENT_FORMAT,
                       coap_encode_var_safe(buf, sizeof(buf), mediatype),
                       buf)) {
    dcaf_log(DCAF_LOG_DEBUG, "DCAF_ERROR_BUFFER_TOO_SMALL\n");
    return DCAF_ERROR_BUFFER_TOO_SMALL;
  }

  /* generate sam information message */
  cn_cbor *map = cn_cbor_map_create(NULL);
  const char *uri = (const char *)dcaf_context->am_uri + sizeof(coap_uri_t);

  /* TODO: fix ACE_ASINFO_AS and ACE_ASINFO_NONCE */
  /* if (!is_dcaf(mediatype)) { */
  /*   sam_key = ACE_ASINFO_AS; */
  /*   nonce_key = ACE_ASINFO_NONCE; */
  /* } */

  dcaf_log(DCAF_LOG_DEBUG, "CBOR...\n");
  cn_cbor_mapput_int(map, sam_key,
                     cn_cbor_string_create(uri, NULL),
                     NULL);
  cn_cbor_mapput_int(map, nonce_key,
                     cn_cbor_int_create(coap_ticks_to_rt(now), NULL),
                     NULL);

#ifdef DCAF_EXTENSIONS
  if (is_dcaf(mediatype)) {
    cn_cbor *accept = cn_cbor_array_create(NULL);
    cn_cbor_array_append(accept,
                         cn_cbor_int_create(DCAF_MEDIATYPE_DCAF_CBOR, NULL),
                         NULL);
  cn_cbor_mapput_int(map, DCAF_TYPE_A, accept, NULL);
  }
#endif /* DCAF_EXTENSIONS */

  length = cn_cbor_encoder_write(buf, 0, sizeof(buf), map);
  cn_cbor_free(map);

  if (!coap_add_data(response, length, buf)) {
    dcaf_log(DCAF_LOG_DEBUG, "also too small\n");
    return DCAF_ERROR_BUFFER_TOO_SMALL;
  }

  response->code = COAP_RESPONSE_CODE(401);
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
  response->code = COAP_RESPONSE_CODE(400);
  coap_add_option(response,
                  COAP_OPTION_CONTENT_FORMAT,
                  coap_encode_var_safe(buf, sizeof(buf),
                                       COAP_MEDIATYPE_TEXT_PLAIN),
                  buf);
  coap_add_data(response, 20, (unsigned char *)"error");
  return DCAF_OK;
}





