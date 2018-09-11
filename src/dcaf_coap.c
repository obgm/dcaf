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
#include <timex.h>
#endif /* RIOT_VERSION */

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_coap.h"

#ifdef RIOT_VERSION

void
coap_ticks(coap_tick_t *t) {
  timex_t tx;
  assert(t);
  *t = timex_uint64(tx);
}  

int
coap_get_content_format(const coap_pdu_t *pdu) {
  /* FIXME */
  return -1;
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

#endif /* RIOT_VERSION */
