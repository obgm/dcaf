/*
 * dcaf_mem.c -- DCAF memory management
 *
 * Copyright (C) 2015-2018 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2018 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <assert.h>
#include <stdint.h>

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_coap.h"

#ifdef RIOT_VERSION
#error need to define memory allocator
#else /* RIOT_VERSION */
#define CHECK_AND_ALLOC(Type, Maxlen, Len)                              \
  (((Maxlen) < (Len)) ? NULL : coap_malloc(sizeof(Type) + (Len)))
#define FREE(Type, Pointer) coap_free(Pointer)
#endif

void *
dcaf_alloc_type_len(dcaf_object_type obj, size_t len) {
  /* FIXME: use static memory allocator on non-posix systems */
  switch (obj) {
  default: return NULL;
  case DCAF_CONTEXT: return CHECK_AND_ALLOC(dcaf_context_t, 0, len);
  case DCAF_AUTHZ: return CHECK_AND_ALLOC(dcaf_authz_t, 0, len);
  case DCAF_TICKET: return CHECK_AND_ALLOC(dcaf_ticket_t, 0, len);
  case DCAF_KEY: return CHECK_AND_ALLOC(dcaf_key_t, DCAF_MAX_KEY_SIZE, len);
  case DCAF_AIF: return CHECK_AND_ALLOC(dcaf_aif_t, 0, len);
  case DCAF_OPTION: return CHECK_AND_ALLOC(dcaf_option_t, DCAF_MAX_OPT_SIZE, len);
  }
}
#undef CHECK_AND_ALLOC

void *
dcaf_alloc_type(dcaf_object_type obj) {
  size_t len = 0;

  switch (obj) {
  default: return NULL;
  case DCAF_CONTEXT: break;
  case DCAF_AUTHZ: break;
  case DCAF_TICKET: break;
  case DCAF_KEY: len = DCAF_MAX_KEY_SIZE; break;
  case DCAF_AIF: break;
  case DCAF_OPTION: len = DCAF_MAX_OPT_SIZE; break;
  }
  return dcaf_alloc_type_len(obj, len);
}

void
dcaf_free_type(dcaf_object_type obj, void *p) {
  /* FIXME: use static memory allocator on non-posix systems */
  switch (obj) {
  case DCAF_CONTEXT: FREE(obj, p); break;
  case DCAF_AUTHZ: FREE(obj, p); break;
  case DCAF_TICKET: FREE(obj, p); break;
  case DCAF_KEY: FREE(obj, p); break;
  case DCAF_AIF: FREE(obj, p); break;
  case DCAF_OPTION: FREE(obj, p);
  default:
    ;
  }
}
#undef FREE
