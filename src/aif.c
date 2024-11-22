/*
 * aif.c -- authorization information format
 *
 * Copyright (C) 2018,2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <ctype.h>

#include "dcaf/dcaf_int.h"
#include "dcaf/utlist.h"
#include "dcaf/aif.h"

dcaf_aif_t *
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
dcaf_aif_parse_string(const abor_decoder_t *cbor, dcaf_aif_t **result) {
  dcaf_result_t res = DCAF_ERROR_INVALID_TICKET;
  dcaf_aif_t *aif;
  assert(cbor);
  assert(result);

  *result = NULL;   /* initialize *result */

  /* if cbor is a string, try to make sense of it */
  if (abor_check_type(cbor, ABOR_TSTR)) {
    size_t len = abor_get_sequence_length(cbor);
    const char *p = abor_get_text(cbor);
    const char *q;

    assert(p || (len == 0));

    while (len) {
      int method;

      for (; len && isspace((uint8_t)*p); len--, p++)
        ;

      /* p now points either to the end or the first non-LWS character */
      if (!len) {
        dcaf_log(DCAF_LOG_DEBUG, "invalid AIF\n");
        return DCAF_ERROR_INVALID_TICKET;
      }

      /* try to parse requested method */
      for (q = p; len && isalpha((uint8_t)*q); len--, q++)
        ;

      method = get_method(p, q - p);
      if (!method) {
        dcaf_log(DCAF_LOG_DEBUG, "invalid method in AIF\n");
        res = DCAF_ERROR_INVALID_TICKET;
        break;
      }

      /* skip whitespace */
      for (p = q; len && isspace((uint8_t)*p); len--, p++)
        ;

      /* try to parse requested URI path */
      for (q = p; len && (isalnum((uint8_t)*q) || ispunct((uint8_t)*q)); len--, q++)
        ;

      if ((q - p) == 0) {
        dcaf_log(DCAF_LOG_DEBUG, "no resource given in AIF\n");
        res = DCAF_ERROR_INVALID_TICKET;
        break;
      }

      /* create dcaf_aif_t */
      aif = dcaf_new_aif();
      if (!aif) {
        dcaf_log(DCAF_LOG_DEBUG, "cannot create AIF object\n");
        res = DCAF_ERROR_OUT_OF_MEMORY;
        break;
      }

      if (p - q > DCAF_MAX_RESOURCE_LEN) {
        dcaf_delete_aif(aif);
        res = DCAF_ERROR_OUT_OF_MEMORY;
        break;
      }
      memcpy(aif->perm.resource, p, q - p);
      aif->perm.resource_len = q - p;
      aif->perm.resource[aif->perm.resource_len] = '\0';
      aif->perm.methods = method;

      LL_PREPEND(*result, aif);
    }
  }

  /* If there are items in *result, we must return DCAF_OK to instruct
   * the caller to release the allocated memory. */
  return (*result != NULL) ? DCAF_OK : res;
}

static inline bool
odd(long n) {
  return (n & 1) != 0;
}

dcaf_result_t
dcaf_aif_parse(abor_decoder_t *cbor, dcaf_aif_t **result) {
  dcaf_result_t res = DCAF_ERROR_INVALID_TICKET;
  dcaf_aif_t *aif;
  abor_iterator_t *it;
  abor_decoder_t *cp;
  enum { NEED_URI, NEED_METHODS } iterator_state = NEED_URI;

  assert(cbor);
  assert(result);

  *result = NULL;   /* initialize *result */

  if (!abor_check_type(cbor, ABOR_ARRAY)) {
    return DCAF_ERROR_INVALID_TICKET;
  }

  /* the number of elements in the array must be even */
  if (odd(abor_get_sequence_length(cbor))) {
    return DCAF_ERROR_INVALID_TICKET;
  }

  /* process AIF array */
  it = abor_iterate_start(cbor);
  if (!it) {
    return DCAF_ERROR_OUT_OF_MEMORY;
  }

  const uint8_t *uri = NULL;
  size_t uri_length = 0;
  do {
    cp = abor_iterate_get(it);

    if (iterator_state == NEED_URI) {
      if (!abor_check_type(cp, ABOR_TSTR) &&
          !abor_check_type(cp, ABOR_BSTR)) {
        res = DCAF_ERROR_INVALID_TICKET;
        goto finish;
      }
      /* get URI and length */
      uri = abor_get_bytes(cp);
      uri_length = abor_get_sequence_length(cp);

      /* resource URI too long; stop as we cannot continue properly */
      if (uri_length > DCAF_MAX_RESOURCE_LEN) {
        res = DCAF_ERROR_OUT_OF_MEMORY;
        goto finish;
      }
    } else { /* NEED_METHODS */
      uint64_t methods;
      /* get methods and create AIF entry */
      if (!abor_get_uint(cp, &methods)) {
        res = DCAF_ERROR_INVALID_TICKET;
        goto finish;
      }

      aif = dcaf_new_aif();
      if (!aif) {
        res = DCAF_ERROR_OUT_OF_MEMORY;
        goto finish;
      }

      if (uri_length) {
        memcpy(aif->perm.resource, uri, uri_length);
        aif->perm.resource_len = uri_length;
      }
      aif->perm.methods = methods;

      LL_PREPEND(*result, aif);
    }
    iterator_state = (iterator_state + 1) % 2;
    abor_decode_finish(cp);
  } while (abor_iterate_next(it));

 finish:
  abor_decode_finish(cp);
  abor_iterate_finish(it);    
  /* If there are items in *result, we must return DCAF_OK to instruct
   * the caller to release the allocated memory. */
  return (*result != NULL) ? DCAF_OK : res;
}

bool
dcaf_aif_to_cbor(const dcaf_aif_t *aif, abor_encoder_t *abc) {
  const dcaf_aif_t *tmp;
  int counter;
  bool ok;

  if (!aif)
    return false;

  /* Count number of AIF items. Each structure results in two array
   * elements. */
  LL_COUNT(aif,tmp,counter);
  ok = abor_write_array(abc, 2 * counter);

  LL_FOREACH(aif, tmp) {
    /* An error in the second write may lead to an incomplete array. */ 
    ok = ok && abor_write_text(abc,
                               (const char *)tmp->perm.resource,
                               tmp->perm.resource_len);
    ok = ok && abor_write_uint(abc, tmp->perm.methods);

    if (!ok) {
      dcaf_log(DCAF_LOG_DEBUG, "out of memory when creating AIF\n");
      break;
    }
  }

  return ok;
}

static bool
uri_matches(const dcaf_aif_permission_t *perm,
            const uint8_t *uri, size_t uri_length) {
  assert(perm);

  /* TODO: partial URI matches/URI templates */
  return (uri_length == perm->resource_len)
    && ((uri_length == 0) || (uri && (strncmp((const char *)uri,
                                              (const char *)perm->resource,
                                              uri_length) == 0)));
}

dcaf_aif_result_t
dcaf_aif_evaluate(const dcaf_aif_t *aif,
                  const coap_pdu_t *pdu) {
  const dcaf_aif_t *elem;
  uint8_t uri[DCAF_MAX_RESOURCE_LEN+1];
  size_t length = sizeof(uri);
  int method;
  int allowed = 0;
  int denied = 0;

  assert(pdu);

  if (!pdu || !aif) {
    return DCAF_AIF_DENIED;
  }

  if (!coap_get_resource_uri(pdu, uri, &length, 0)) {
    return DCAF_AIF_ERROR;
  }

  method = coap_get_method(pdu);

  /* Traverse aif list and check for each matching URI whether the
   * permissions explicitly allow or deny the request. The result
   * should be DCAF_AIF_ALLOW only if there is at least one permission
   * that allows the request and none that denies it. */
  LL_FOREACH(aif, elem) {
    if (uri_matches(&elem->perm, uri, length)) {
      if ((elem->perm.methods & method) > 0) 
        allowed++;
      else 
        denied++;
    }
  }

  /*
    (allowed && !denied) evaluates to 1 -> DCAF_AIF_ALLOWED (==1)
                         evaluates to 0 -> DCAF_AIF_DENIED  (==0)
  */
  return (allowed && !denied);
}
