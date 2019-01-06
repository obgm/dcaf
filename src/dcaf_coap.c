/*
 * dcaf_coap.c -- DCAF CoAP function wrapper
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *               2018 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <assert.h>
#include <stdint.h>

#ifdef RIOT_VERSION
#include <xtimer.h>
#endif /* RIOT_VERSION */

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_coap.h"

#ifdef RIOT_VERSION

void
coap_ticks(coap_tick_t *t) {
  assert(t);
  *t = xtimer_now_usec64();
}  

coap_time_t
coap_ticks_to_rt(coap_tick_t t) {
  return t / 1000000UL;
}

int
coap_get_content_format(const coap_pdu_t *pdu) {
  return coap_get_content_type((coap_pdu_t *)pdu);
}

int
coap_get_data(coap_pdu_t *pkt, size_t *len, unsigned char **data) {
  assert(pkt != NULL);
  assert(len != NULL);

  if (pkt) {
    *len = pkt->payload_len;
    if (data) {
      *data = pkt->payload;
    }
  } else {
    *len = 0;
  }
  return *len > 0;
}

int
coap_add_data(coap_pdu_t *pkt,
              unsigned int len,
              const unsigned char *data) {
  assert(pkt != NULL);

  if (pkt) {
    pkt->payload = dcaf_alloc_type_len(DCAF_STRING, len);
    if (pkt->payload) {
      pkt->payload_len = len;
      memcpy(pkt->payload, data, pkt->payload_len);
      return 1;
    }
  }
  return 0;
}
#else /* !RIOT_VERSION */

int
coap_get_content_format(const coap_pdu_t *pdu) {
  if (pdu) {
    coap_opt_iterator_t iter;
    coap_option_t content_format;
    coap_opt_t *opt;

    /* Need to cast pdu as coap_check_option() does not take const */
    opt = coap_check_option((coap_pdu_t *)pdu, COAP_OPTION_CONTENT_FORMAT, &iter);
    if (opt && (coap_opt_parse(opt, coap_opt_size(opt), &content_format) > 0))
      return coap_decode_var_bytes(content_format.value, content_format.length);
  }
  return -1;
}

const uint8_t *
coap_get_token(const coap_pdu_t *pdu) {
  assert(pdu);
  return pdu->token;
}

size_t
coap_get_token_length(const coap_pdu_t *pdu) {
  assert(pdu);
  return pdu->token_length;
}

uint8_t
coap_get_method(const coap_pdu_t *pdu) {
  assert(pdu);
  return pdu->code;
}

int
coap_get_resource_uri(const coap_pdu_t *pdu,
                      uint8_t *buf, size_t *buf_len,
                      int flags) {
  coap_string_t *uri;
  int result = 0;
  (void)flags;

  assert(pdu);
  assert(buf);
  assert(buf_len);

  uri = coap_get_uri_path(pdu);
  if (!uri) { /* This is an error */
    *buf_len = 0;
    return 0;
  }

  if (uri->length <= *buf_len) {   /* copy entire URI */
    memcpy(buf, uri->s, uri->length);
    result = *buf_len = uri->length;
  } else {                      /* copy only *buf_len bytes */
    memcpy(buf, uri->s, *buf_len);
    result = 0;
  }

  coap_delete_string(uri);
  return result;
}

#endif /* RIOT_VERSION */
