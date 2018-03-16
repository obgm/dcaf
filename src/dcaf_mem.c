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

void *
dcaf_alloc_type(dcaf_object_type obj) {
  /* FIXME: use static memory allocator on non-posix systems */
  switch (obj) {
  default: return NULL;
  case DCAF_CONTEXT: return coap_malloc(sizeof(dcaf_context_t));
  case DCAF_TICKET: return coap_malloc(sizeof(dcaf_ticket_t));
  case DCAF_KEY: return coap_malloc(sizeof(dcaf_key_t) + DCAF_MAX_KEY_SIZE);
  }
}

void
dcaf_free_type(dcaf_object_type obj, void *p) {
  /* FIXME: use static memory allocator on non-posix systems */
  switch (obj) {
  case DCAF_CONTEXT: coap_free(p); break;
  case DCAF_TICKET: coap_free(p); break;
  case DCAF_KEY: coap_free(p); break;
  default:
    ;
  }
}
