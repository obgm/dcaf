/*
 * aif.c -- authorization information format
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <ctype.h>

#include <coap/utlist.h>

#include "dcaf/dcaf_int.h"
#include "dcaf/aif.h"

static dcaf_aif_t *
dcaf_new_aif(void) {
  dcaf_aif_t *aif = dcaf_alloc_type(DCAF_AIF);
  if (aif) {
    memset(aif, 0, sizeof(dcaf_aif_t));
  }
  return aif;
}

void
dcaf_delete_aif(dcaf_aif_t *aif) {
  dcaf_aif_t *item, *tmp;

  LL_FOREACH_SAFE(aif, item, tmp) {
    dcaf_free_type(DCAF_AIF, item);
  }
}

static uint32_t
get_method(const char *s, size_t len) {
  static const char *known_methods[] = {
    "GET", "POST", "PUT", "DELETE", "FETCH", "PATCH", "IPATCH"
  };
  size_t n;
  for (n = 0; n < (sizeof(known_methods)/sizeof(known_methods[0])); n++) {
    if ((len == strlen(known_methods[n])) &&
        (memcmp(s, known_methods[n], len) == 0)) {
      return (1 << n);
    }
  }
  return 0;
}

dcaf_result_t
dcaf_aif_parse(const cn_cbor *cbor, dcaf_aif_t **result) {
  dcaf_aif_t *aif;
  assert(cbor);
  assert(result);

  *result = NULL;   /* initialize *result */

  /* if cbor is a string, try to make sense of it */
  if (cbor->type == CN_CBOR_TEXT) {
    const char *p, *q;
    size_t len = cbor->length;  /* keep track of remaining length */

    while (len) {
      int method;

      for (p = cbor->v.str; len && isspace(*p); len--, p++)
        ;

      /* p now points either to the end or the first non-LWS character */
      if (!len) {
        dcaf_log(DCAF_LOG_DEBUG, "invalid AIF\n");
        return DCAF_ERROR_INVALID_AIF;
      }
    
      /* try to parse requested method */
      for (q = p; len && isalpha(*q); len--, q++)
        ;

      method = get_method(p, q - p);
      if (!method) {
        dcaf_log(DCAF_LOG_DEBUG, "invalid method in AIF\n");
        return DCAF_ERROR_INVALID_AIF;
      }

      /* skip whitespace */
      for (p = q; len && isspace(*p); len--, p++)
        ;

      /* try to parse requested URI path */
      for (q = p; len && (isalnum(*q) || ispunct(*q)); len--, q++)
        ;

      if ((q - p) == 0) {
        dcaf_log(DCAF_LOG_DEBUG, "no resource given in AIF\n");
        return DCAF_ERROR_INVALID_AIF;
      }

      /* create dcaf_aif_t */
      aif = dcaf_new_aif();
      if (!aif) {
        dcaf_log(DCAF_LOG_DEBUG, "cannot create AIF object\n");
        return DCAF_ERROR_OUT_OF_MEMORY;
      }

      aif->perm.resource = (uint8_t *)p;
      aif->perm.resource_len = q - p;
      aif->perm.methods = method;

      LL_PREPEND(*result, aif);
    }
  }

  if (cbor->type == CN_CBOR_ARRAY) {
    /* FIXME: process AIF array */
  }

  return DCAF_OK;
}

