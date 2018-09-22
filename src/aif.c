/*
 * aif.c -- authorization information format
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <ctype.h>

#include <cn-cbor/cn-cbor.h>

#include "dcaf/dcaf_int.h"
#include "dcaf/utlist.h"
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
dcaf_aif_parse_string(const cn_cbor *cbor, dcaf_aif_t **result) {
  dcaf_result_t res = DCAF_ERROR_INVALID_TICKET;
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
        return DCAF_ERROR_INVALID_TICKET;
      }

      /* try to parse requested method */
      for (q = p; len && isalpha(*q); len--, q++)
        ;

      method = get_method(p, q - p);
      if (!method) {
        dcaf_log(DCAF_LOG_DEBUG, "invalid method in AIF\n");
        res = DCAF_ERROR_INVALID_TICKET;
        break;
      }

      /* skip whitespace */
      for (p = q; len && isspace(*p); len--, p++)
        ;

      /* try to parse requested URI path */
      for (q = p; len && (isalnum(*q) || ispunct(*q)); len--, q++)
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
dcaf_aif_parse(const cn_cbor *cbor, dcaf_aif_t **result) {
  dcaf_result_t res = DCAF_ERROR_INVALID_TICKET;
  dcaf_aif_t *aif;
  const cn_cbor *cp;
  assert(cbor);
  assert(result);

  *result = NULL;   /* initialize *result */

  if (cbor->type != CN_CBOR_ARRAY) {
    return DCAF_ERROR_INVALID_TICKET;
  }

  /* the number of elements in the array must be even */
  if (odd(cbor->length)) {
    return DCAF_ERROR_INVALID_TICKET;
  }

  /* process AIF array */
  cp = cbor->first_child;

  while (cp) {
    assert(cp->next);

    if (((cp->type != CN_CBOR_TEXT) && (cp->type != CN_CBOR_BYTES))
        || (cp->next->type != CN_CBOR_UINT)) {
      break;
    }

    aif = dcaf_new_aif();
    if (!aif) {
      res = DCAF_ERROR_OUT_OF_MEMORY;
      break;
    }

    if (cp->length > DCAF_MAX_RESOURCE_LEN) {
      dcaf_delete_aif(aif);
      res = DCAF_ERROR_OUT_OF_MEMORY;
      break;
    }
    memcpy(aif->perm.resource, cp->v.bytes, cp->length);
    aif->perm.resource_len = cp->length;
    aif->perm.methods = cp->next->v.uint;

    LL_PREPEND(*result, aif);
    cp = cp->next->next;
  }

  /* If there are items in *result, we must return DCAF_OK to instruct
   * the caller to release the allocated memory. */
  return (*result != NULL) ? DCAF_OK : res;
}

cn_cbor *
dcaf_aif_to_cbor(const dcaf_aif_t *aif) {
  cn_cbor *result;
  const dcaf_aif_t *tmp;

  if (!aif || !(result = cn_cbor_array_create(NULL))) {
    return NULL;
  }

  LL_FOREACH(aif, tmp) {
    cn_cbor *resource, *methods;
    resource = cn_cbor_string_create((const char *)tmp->perm.resource,
                                   NULL);
    methods =  cn_cbor_int_create(tmp->perm.methods, NULL);

    if (!resource || !methods) {
      dcaf_log(DCAF_LOG_DEBUG, "out of memory when creating AIF\n");
      cn_cbor_free(resource);
      cn_cbor_free(methods);
      break;
    }

    cn_cbor_array_append(result, resource, NULL);
    cn_cbor_array_append(result, methods, NULL);
  }

  if (result->length == 0) {
    /* we ran out of memory during AIF creation, so just give up */
    cn_cbor_free(result);
    return NULL;
  } else {
    return result;
  }
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
