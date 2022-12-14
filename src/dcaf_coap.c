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

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_coap.h"

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
  coap_bin_const_t token;
  assert(pdu);
  token = coap_pdu_get_token(pdu);
  return token.s;
}

size_t
coap_get_token_length(const coap_pdu_t *pdu) {
  coap_bin_const_t token;
  assert(pdu);
  token = coap_pdu_get_token(pdu);
  return token.length;
}

uint8_t
coap_get_method(const coap_pdu_t *pdu) {
  assert(pdu);
  return (uint8_t)(coap_pdu_get_code(pdu) & 0xFF);
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
