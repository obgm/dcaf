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

#include <cn-cbor/cn-cbor.h>

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/state.h"

#include "dcaf/ace.h"
#include "dcaf/cwt.h"
#include "dcaf/cose.h"

static inline int
token_equals(coap_pdu_t *a, coap_pdu_t *b) {
  return a && b && (a->token_length == b->token_length)
    && (strncmp((char *)a->token, (char *)b->token,
                a->token_length) == 0);
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

  (void)session;
  (void)sent;
  (void)id;

  dcaf_context = dcaf_get_dcaf_context(coap_context);
  assert(dcaf_context);

  t = dcaf_find_transaction(dcaf_context, &session->remote_addr, received);
  if (!t) {
    coap_log(LOG_ERR, "dropped response for unknown transaction\n");
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
    coap_log(LOG_ALERT, "unknown transaction state\n");
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
  if (LOG_DEBUG <= coap_get_log_level()) {
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
  return coap_new_endpoint(dcaf_context->coap_context, addr, proto) != NULL;
}

dcaf_ticket_t *dcaf_tickets = NULL;

dcaf_ticket_t *
dcaf_find_ticket(const uint8_t *kid, size_t kid_length) {
  dcaf_ticket_t *ticket = NULL;
  LL_FOREACH(dcaf_tickets,ticket) {
    if ((kid_length == ticket->kid_length)
        && (memcmp(kid, ticket->kid, ticket->kid_length) == 0)) {
      return ticket;
    }
  }
  return NULL;
}

dcaf_ticket_t *
dcaf_new_ticket(const uint8_t *kid, size_t kid_length,
                const uint8_t *verifier, size_t verifier_length) {
  dcaf_ticket_t *ticket = (dcaf_ticket_t *)dcaf_alloc_type(DCAF_TICKET);
  if (ticket) {
    memset(ticket, 0, sizeof(dcaf_ticket_t));
    if (kid && kid_length) {
      ticket->kid = (uint8_t *)coap_malloc(kid_length);
      if (ticket->kid) {
        memcpy(ticket->kid, kid, kid_length);
        ticket->kid_length = kid_length;
      }
    }
    if (verifier && verifier_length) {
      ticket->verifier = (uint8_t *)coap_malloc(verifier_length);
      if (ticket->verifier) {
        memcpy(ticket->verifier, verifier, verifier_length);
        ticket->verifier_length = verifier_length;
      }
    }
  }
  return ticket;
}

void
dcaf_add_ticket(dcaf_ticket_t *ticket) {
  LL_PREPEND(dcaf_tickets, ticket);
}

void
dcaf_free_ticket(dcaf_ticket_t *ticket) {
  if (ticket) {
    coap_free(ticket->kid);
    coap_free(ticket->verifier);
    dcaf_free_type(DCAF_TICKET, ticket);
  }
}

static size_t
dcaf_get_server_psk(const coap_session_t *session,
                    const uint8_t *identity, size_t identity_len,
                    uint8_t *psk, size_t max_psk_len) {
  (void)identity;
  (void)identity_len;
  const coap_context_t *ctx = session->context;
  if (ctx) {
    dcaf_ticket_t *t = dcaf_find_ticket(identity, identity_len);
    if (!t) { /* FIXME: create new ticket if possible */
      dcaf_log(LOG_DEBUG, "no ticket found\n");
    }

    if (t && t->verifier && (t->verifier_length <= max_psk_len)) {
      memcpy(psk, t->verifier, t->verifier_length);
      return t->verifier_length;
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
    dcaf_log(LOG_EMERG, "cannot allocate context\n");
    goto error;
  }

  memset(dcaf_context, 0, sizeof(dcaf_context_t));

  dcaf_context->coap_context = coap_new_context(NULL);
  if (dcaf_context->coap_context == NULL) {
    dcaf_log(LOG_EMERG, "Cannot create new CoAP context.\n");
    goto error;
  }

  dcaf_context->coap_context->get_server_psk = dcaf_get_server_psk;
  coap_set_app_data(dcaf_context->coap_context, dcaf_context);

  if (config && config->host) {
    addr_str = config->host;
  }

  if (dcaf_set_coap_address((const unsigned char *)addr_str, strlen(addr_str),
                            coap_port(config), &addr) == DCAF_OK) {
    if (set_endpoint(dcaf_context, &addr, COAP_PROTO_UDP)) {
      unsigned char buf[INET6_ADDRSTRLEN + 8];

      if (coap_print_addr(&addr, buf, INET6_ADDRSTRLEN + 8)) {
        dcaf_log(LOG_INFO, "listen on address %s (UDP)\n", buf);
      }
    }
  }

  if (dcaf_set_coap_address((const unsigned char *)addr_str, strlen(addr_str),
                            coaps_port(config), &addr) == DCAF_OK) {
    if (set_endpoint(dcaf_context, &addr, COAP_PROTO_DTLS)) {
      unsigned char buf[INET6_ADDRSTRLEN + 8];

      if (coap_print_addr(&addr, buf, INET6_ADDRSTRLEN + 8)) {
        dcaf_log(LOG_INFO, "listen on address %s (DTLS)\n", buf);
      }
    }
  }

  /* set am_uri from config->am_uri */
  if (config && config->am_uri) {
    dcaf_set_am_uri(dcaf_context,
                    (const unsigned char *)config->am_uri,
                    strlen(config->am_uri));
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
    coap_free(context->am_uri);
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

int
dcaf_is_authorized(const coap_session_t *session,
                   coap_pdu_t *pdu) {
  if (is_secure(session)) {
    /* FIXME: retrieve and check ticket */
    coap_log(LOG_DEBUG, "PSK identity is '%.*s':\n",
             (int)session->psk_identity_len, (char *)session->psk_identity);
    return pdu != NULL;
  }
  return 0;
}

/* Returns true iff DCAF should be used. */
static bool
is_dcaf(dcaf_mediatype_t mediatype) {
  return mediatype != DCAF_MEDIATYPE_ACE_CBOR;
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

  coap_log(LOG_DEBUG, "create SAM Information\n");
  coap_ticks(&now);
  assert(session != NULL);
  assert(session->context != NULL);
  assert(response != NULL);

  if (!session || !response) {
    return DCAF_ERROR_INTERNAL_ERROR;
  }
  dcaf_context = dcaf_get_dcaf_context(session->context);
  if (!dcaf_context) {
    coap_log(LOG_DEBUG, "DCAF_ERROR_INTERNAL_ERROR\n");
    return DCAF_ERROR_INTERNAL_ERROR;
  }

  /* The DCAF unauthorized response is constructed only when a proper
   * SAM URI is set. */
  if (!dcaf_context->am_uri) {
    coap_log(LOG_DEBUG, "no SAM URI\n");
    response->code = COAP_RESPONSE_CODE(401);
    return DCAF_OK;
  }

  if (!coap_add_option(response, COAP_OPTION_CONTENT_TYPE,
                       coap_encode_var_bytes(buf, mediatype), buf)) {
    coap_log(LOG_DEBUG, "DCAF_ERROR_BUFFER_TOO_SMALL\n");
    return DCAF_ERROR_BUFFER_TOO_SMALL;
  }

  /* generate sam information message */
  cn_cbor *map = cn_cbor_map_create(NULL);
  const char *uri = (const char *)dcaf_context->am_uri + sizeof(coap_uri_t);

  if (!is_dcaf(mediatype)) {
    sam_key = ACE_ASINFO_AS;
    nonce_key = ACE_ASINFO_NONCE;
  }

  coap_log(LOG_DEBUG, "CBOR...\n");
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
    coap_log(LOG_DEBUG, "also too small\n");
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
                  COAP_OPTION_CONTENT_TYPE,
                  coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
  coap_add_data(response, 20, (unsigned char *)"error");
  return DCAF_OK;
}

/* helper function to log cn-cbor parse errors */
static inline void
log_parse_error(const cn_cbor_errback err) {
  dcaf_log(DCAF_LOG_ERR, "parse error %d at pos %d\n", err.err, err.pos);
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

/**
 * Parses @p data into @p result. This function returns true on
 * success, or false on error.
 *
 * @param data      The token request to parse.
 * @param data_len  The actual size of @p data.
 * @param result    The result object if true.
 *
 * @return false on parse error, true otherwise.
 */
static bool
parse_token_request(const uint8_t *data,
                    size_t data_len,
                    dcaf_authz_t *result) {
  cn_cbor_errback errp;
  const cn_cbor *token_request;
  const cn_cbor *cnf, *k, *scope;

  assert(data);
  assert(result);

  token_request = cn_cbor_decode(data, data_len, &errp);

  if (!token_request) {
    log_parse_error(errp);
    result->code = DCAF_ERROR_BAD_REQUEST;
    return false;
  }

  cnf = cn_cbor_mapget_int(token_request, CWT_CLAIM_CNF);
  if (!cnf) {
    result->code = DCAF_ERROR_BAD_REQUEST;
    goto finish;
  }

  /* check contents of cnf item */
  if (cnf->type != CN_CBOR_MAP) {
    dcaf_log(LOG_DEBUG, "invalid cnf value in token request\n");
    result->code = DCAF_ERROR_BAD_REQUEST;
    goto finish;
  }

  k = cn_cbor_mapget_int(cnf, CWT_CNF_KID);
  if (k) {
    /* TODO: check if kid is allowed for this session */
    result->code = DCAF_ERROR_UNSUPPORTED_KEY_TYPE;
  } else {
    if ((k = get_cose_key(cnf)) != NULL) {
      /* TODO: check if kty is ECC */
      cn_cbor *kty = cn_cbor_mapget_int(k, COSE_KEY_KTY);
      if (kty && kty->v.sint == COSE_KEY_KTY_SYMMETRIC) {
        /* token requests must not contain a symmetric key */
        dcaf_log(LOG_DEBUG, "kty=symmetric not allowed in token request\n");
        result->code = DCAF_ERROR_BAD_REQUEST;
      } else {
        /* TODO: ECC key */
        result->code = DCAF_ERROR_UNSUPPORTED_KEY_TYPE;
      }
    }
  }

  scope = cn_cbor_mapget_int(cnf, ACE_CLAIM_SCOPE);
  if (scope) {
    /* TODO: parse AIF */
  }

 finish:
  cn_cbor_free((cn_cbor *)token_request);
  return true;
}

dcaf_authz_t *
dcaf_new_authz(void) {
  dcaf_authz_t *result = dcaf_alloc_type(DCAF_AUTHZ);
  if (result) {
    memset(result, 0, sizeof(dcaf_authz_t));
  }
  return result;
}

void
dcaf_delete_authz(dcaf_authz_t *authz) {
  if (authz && authz->key) {
    dcaf_delete_key(authz->key);
  }

  dcaf_free_type(DCAF_AUTHZ, authz);
}

dcaf_authz_t *
dcaf_parse_authz_request(const coap_session_t *session,
                         const coap_pdu_t *request) {
  static dcaf_authz_t tmp;
  (void)session;

  /* check if this is the correct SAM,
       SAM: "coaps://sam.example.com/authorize",
        SAI: ["coaps://temp451.example.com/s/tempC", 5],
        TS: 168537
      }
  */
  coap_opt_iterator_t oi;
  coap_opt_t *option =
    coap_check_option((coap_pdu_t *)request, COAP_OPTION_CONTENT_FORMAT, &oi);
  coap_option_t accept;
  uint8_t *payload = NULL;
  size_t payload_len = 0;

  tmp.mediatype = DCAF_MEDIATYPE_ACE_CBOR;
  if (option && coap_opt_parse(option, coap_opt_size(option), &accept) > 0) {
    tmp.mediatype = coap_decode_var_bytes(accept.value, accept.length);
  }
  if ((tmp.mediatype != DCAF_MEDIATYPE_ACE_CBOR) &&
      (tmp.mediatype != DCAF_MEDIATYPE_DCAF_CBOR)) {
    dcaf_log(DCAF_LOG_WARNING, "unknown content format\n");
    tmp.code = DCAF_ERROR_BAD_REQUEST;
    goto finish;
  }

  /* retrieve payload */
  if (!coap_get_data((coap_pdu_t *)request, &payload_len, &payload)) {
    dcaf_log(DCAF_LOG_WARNING, "drop request with empty payload\n");
    tmp.code = DCAF_ERROR_BAD_REQUEST;
    goto finish;
  }

  if (!parse_token_request(payload, payload_len, &tmp)) {
    /* use result code that was set by parse_token_request() */
    dcaf_log(DCAF_LOG_WARNING, "unknown content format\n");
    goto finish;
  }
  /* TODO: check aud, scope, token_type */

  tmp.code = DCAF_OK;
  tmp.lifetime = DCAF_DEFAULT_LIFETIME;
 finish:
  return &tmp;
}

#define MAJOR_TYPE_BYTE_STRING (2 << 5)

dcaf_result_t
dcaf_create_verifier(dcaf_context_t *ctx, dcaf_authz_t *authz) {
  (void)ctx;
  assert(authz);

  /* FIXME:
   *     - check if we need to generate a new key
   *     - support key generation, e.g. HKDF-based
   */
  if (authz->key == NULL) {
    authz->key = dcaf_new_key(DCAF_AES_128);
    if (!authz->key || !dcaf_key_rnd(authz->key)) {
      dcaf_delete_key(authz->key);
      return DCAF_ERROR_UNSUPPORTED_KEY_TYPE;
    }
    dcaf_log(LOG_DEBUG, "generated key:\n");
    dcaf_debug_hexdump(authz->key->data, authz->key->length);
    return DCAF_OK;
  }
#if 0
  size_t len;
  if (!(out_length && (*out_length > 2))) {
    return DCAF_ERROR_BUFFER_TOO_SMALL;
  }

  len = *out_length - 2;
  if (dcaf_hmac(params, face, face_length, output + 2, &len)) {
    output[0] = MAJOR_TYPE_BYTE_STRING | 25;
    output[1] = len;          /* TODO: handle len < 24 or len > 255 */
    *out_length = len + 2;
    return DCAF_OK;
  }
#endif

  dcaf_log(LOG_DEBUG, "dcaf_create_verifier: key should have been NULL\n");
  return DCAF_ERROR_INTERNAL_ERROR;
}

static cn_cbor *
make_cose_key(const dcaf_key_t *key) {
  cn_cbor *map, *cose_key;

  assert(key);

  if ((map = cn_cbor_map_create(NULL)) == NULL) {
    dcaf_log(DCAF_LOG_DEBUG, "cannot create COSE key: insufficient memory\n");
    return NULL;
  }

  cn_cbor_mapput_int(map, COSE_KEY_KTY,
                     cn_cbor_int_create(COSE_KEY_KTY_SYMMETRIC, NULL),
                     NULL);

  /* set kid or k, depending on type (TODO: may want to set both) */
  if (key->type == DCAF_KID) {
    cn_cbor_mapput_int(map, COSE_KEY_KID,
                       cn_cbor_data_create(key->data, key->length, NULL),
                       NULL);
  } else {
    assert(key->data);
    cn_cbor_mapput_int(map, COSE_KEY_K,
                       cn_cbor_data_create(key->data, key->length, NULL),
                       NULL);
  }

  if ((cose_key = cn_cbor_map_create(NULL)) == NULL) {
    dcaf_log(DCAF_LOG_DEBUG, "cannot create COSE key wrapper: insufficient memory\n");
    cn_cbor_free(map);
    return NULL;
  }

  cn_cbor_mapput_int(map, CWT_COSE_KEY, cose_key, NULL);
  return map;
}

static cn_cbor *
make_ticket_face(const dcaf_authz_t *authz) {
  const char uri[] = "/s/tempC";
  cn_cbor *map = cn_cbor_map_create(NULL);

  assert(authz != NULL);

  if (is_dcaf(authz->mediatype)) { /* DCAF_MEDIATYPE_DCAF_CBOR */
    cn_cbor *sai = cn_cbor_array_create(NULL);
    cn_cbor_array_append(sai, cn_cbor_string_create(uri, NULL), NULL);
    cn_cbor_array_append(sai, cn_cbor_int_create(7, NULL), NULL);
    /* TODO: TS */
    cn_cbor_mapput_int(map, DCAF_TYPE_SAI, sai, NULL);
    cn_cbor_mapput_int(map, DCAF_TYPE_L,
                       cn_cbor_int_create(authz->lifetime, NULL),
                       NULL);
    cn_cbor_mapput_int(map, DCAF_TYPE_G,
                       cn_cbor_int_create(authz->key->type, NULL),
                       NULL);
  } else {
    cn_cbor_mapput_int(map, ACE_CLAIM_SCOPE,
                       cn_cbor_string_create(uri, NULL),
                       NULL);
    if (authz->ts > 0) {
      cn_cbor_mapput_int(map, CWT_CLAIM_IAT,
                         cn_cbor_int_create(authz->ts, NULL),
                         NULL);
    }
    cn_cbor_mapput_int(map, ACE_CLAIM_CNF, make_cose_key(authz->key), NULL);
  }

  /* encrypt ticket face*/
  {
    unsigned char buf[128], out[143];
    size_t outlen = sizeof(out);
    size_t buf_len;
    static dcaf_key_t rs_key = {
      .length = 11,
    };
    memcpy(rs_key.data, "RS's secret",rs_key.length);

    /* write cbor face to buf, buf_len */
    buf_len = cn_cbor_encoder_write(buf, 0, sizeof(buf), map);
    cn_cbor_free(map);
    map = NULL;

#if 0  /* FIXME: need to create a valid COSE_Encrypt0 object */
    if (cose_encrypt0(COSE_AES_CCM_16_64_128, &rs_key,
                      NULL, 0, buf, &buf_len, &map) != COSE_OK) {
      /* encrypt failed! */
      dcaf_log(DCAF_LOG_CRIT, "cose_encrypt0: failed\n");
      return NULL;
    }
#endif
  }
  return map;
}

void
dcaf_set_ticket_grant(const coap_session_t *session,
                      const dcaf_authz_t *authz,
                      coap_pdu_t *response) {
  dcaf_context_t *ctx;
  unsigned char buf[128];
  size_t length = 0;

  ctx = (dcaf_context_t *)coap_get_app_data(session->context);
  assert(ctx);

  if (dcaf_create_verifier(ctx, (dcaf_authz_t *)authz) != DCAF_OK) {
    dcaf_log(DCAF_LOG_CRIT, "cannot create verifier\n");
    response->code = COAP_RESPONSE_CODE(500);
    coap_add_data(response, 14, (unsigned char *)"internal error");
    return;
  }

  response->code = COAP_RESPONSE_CODE(201);
  coap_add_option(response,
                  COAP_OPTION_CONTENT_TYPE,
                  coap_encode_var_bytes(buf, authz->mediatype), buf);

  coap_add_option(response,
                  COAP_OPTION_MAXAGE,
                  coap_encode_var_bytes(buf, 90), buf);

  /* generate ticket grant depending on media type */
  if (authz->mediatype == DCAF_MEDIATYPE_DCAF_CBOR) {
    buf[0] = 0xa2; /* map(2) */
    buf[1] = DCAF_TYPE_F; /* unsigned int */
    cn_cbor *face = make_ticket_face(authz);

    length = cn_cbor_encoder_write(buf, 2, sizeof(buf), face);
    /* TODO: create verifier over buf and append to map */

    buf[length + 2] = DCAF_TYPE_V; /* unsigned int */

#if 0
    switch (authz->key->type) {
    case DCAF_KEY_HMAC_SHA256:
      /* fall through */
    case DCAF_KEY_HMAC_SHA384:
      /* fall through */
    case DCAF_KEY_HMAC_SHA512: {
      const size_t face_length = length;
      size_t len = sizeof(buf) - length;
      dcaf_crypto_param_t params = {
        .alg = DCAF_HS256,    /* TODO: support for additional types */
        .params.key = authz->key
      };
      length += 3;
      if (dcaf_create_verifier(&params, buf + 3, face_length,
                               buf + length, &len) == DCAF_OK) {
        length += len;
      }
      break;
    }
    case DCAF_AES_CCM_16_64_128: {
      /* TODO */
      break;
    }
    default:
      ;
    }
#endif
    cn_cbor_free(face);
  } else if (authz->mediatype == DCAF_MEDIATYPE_ACE_CBOR) {
    cn_cbor *map = cn_cbor_map_create(NULL);
    cn_cbor *face = make_ticket_face(authz);
    cn_cbor_mapput_int(map, ACE_CLAIM_ACCESS_TOKEN, face, NULL);
    cn_cbor_mapput_int(map, ACE_CLAIM_TOKEN_TYPE,
                       cn_cbor_int_create(ACE_TOKEN_POP, NULL),
                       NULL);
    cn_cbor_mapput_int(map, ACE_CLAIM_EXPIRES_IN,
                       cn_cbor_int_create(authz->lifetime, NULL),
                       NULL);
    cn_cbor_mapput_int(map, ACE_CLAIM_PROFILE,
                       cn_cbor_int_create(ACE_PROFILE_DTLS, NULL),
                       NULL);
    cn_cbor_mapput_int(map, ACE_CLAIM_CNF, make_cose_key(authz->key), NULL);
    length = cn_cbor_encoder_write(buf, 0, sizeof(buf), map);
    cn_cbor_free(map);
  }

  if (length > 0) {
    coap_add_data(response, length, buf);
  }
}
