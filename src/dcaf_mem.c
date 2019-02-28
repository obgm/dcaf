/*
 * dcaf_mem.c -- DCAF memory management
 *
 * Copyright (C) 2015-2018 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2018 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 *
 *Extended by Sara Stadler 2018/2019
 */

#include <assert.h>
#include <stdint.h>

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_coap.h"
#include "dcaf/dcaf_rules.h"
#include "dcaf/dcaf_abc.h"
#include "dcaf/aif.h"

#ifdef RIOT_VERSION
/* FIXME: use static memory allocator */
#define CHECK_AND_ALLOC(Type, Maxlen, Len)                              \
  (((Maxlen) < (Len)) ? NULL : coap_malloc(sizeof(Type) + (Len)))
#define FREE(Type, Pointer) coap_free(Pointer)
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
  case DCAF_TICKET: return CHECK_AND_ALLOC(dcaf_ticket_t, 0, len);
  case DCAF_KEY: return CHECK_AND_ALLOC(dcaf_key_t, DCAF_MAX_KEY_SIZE, len);
  case DCAF_AIF: return CHECK_AND_ALLOC(dcaf_aif_t, 0, len);
  case DCAF_STRING: return CHECK_AND_ALLOC(char[DCAF_MAX_STRING], DCAF_MAX_STRING, len);
  case DCAF_VAR_STRING: return CHECK_AND_ALLOC(char[len], len, len);
  case DCAF_STRING_STR: return CHECK_AND_ALLOC(struct str_st, 0, len);
  case DCAF_DEP_TICKET: return CHECK_AND_ALLOC(dcaf_dep_ticket_t, 0, len);
  case DCAF_TRANSACTION: return CHECK_AND_ALLOC(dcaf_transaction_t, 0, len);
  case DCAF_NONCE: return CHECK_AND_ALLOC(dcaf_nonce_t, 0, len); /* TODO: check */
  case DCAF_TICKET_REQUEST: return CHECK_AND_ALLOC(struct dcaf_ticket_request_t, 0, len);
  case DCAF_ATTRIBUTE_REQUEST: return CHECK_AND_ALLOC(struct dcaf_attribute_request_t, 0, len);
  case DCAF_RULE_LIST: return CHECK_AND_ALLOC(struct rule_list_st, 0, len);
  case DCAF_AIF_PERMISSIONS: return CHECK_AND_ALLOC(struct dcaf_aif_permission_t, 0, len);
  case DCAF_ATTRIBUTE_CONDITIONS: return CHECK_AND_ALLOC(struct attribute_conditions_st, 0, len);
  case DCAF_ATTRIBUTE_RULE_LIST: return CHECK_AND_ALLOC(struct attribute_rule_list_st, 0, len);
  case DCAF_ATTRIBUTE_PERMISSION_LIST: return CHECK_AND_ALLOC(struct attribute_permission_list_st, 0, len);
  case DCAF_ATTRIBUTE_LIST: return CHECK_AND_ALLOC(struct attribute_list_st, 0, len);
  case DCAF_CREDENTIAL_LIST: return CHECK_AND_ALLOC(struct credential_list_st, 0, len);
  case DCAF_CREDENTIAL_STORE: return CHECK_AND_ALLOC(struct credential_store_st, 0, len);
  case DCAF_ISSUER: return CHECK_AND_ALLOC(struct issuer_st, 0, len);
  }
}
#undef CHECK_AND_ALLOC

void *
dcaf_alloc_type(dcaf_object_type obj) {
  size_t len = 0;

  switch (obj) {
  default: return NULL;
  case DCAF_CONTEXT: break;
  case DCAF_TICKET: break;
  case DCAF_KEY: len = DCAF_MAX_KEY_SIZE; break;
  case DCAF_AIF: break; 
  case DCAF_STRING: len = DCAF_MAX_STRING; break;
  case DCAF_VAR_STRING: len = DCAF_CREDEDITAL_MAX_BUF_SIZE; break; //var string should be allocated by dcaf_alloc_type_len
  case DCAF_STRING_STR: break;
  case DCAF_DEP_TICKET: break;
  case DCAF_TRANSACTION: break;
  case DCAF_NONCE: break;
  case DCAF_TICKET_REQUEST: break;
  case DCAF_ATTRIBUTE_REQUEST: break;
  case DCAF_RULE_LIST: break;
  case DCAF_AIF_PERMISSIONS: break;
  case DCAF_ATTRIBUTE_CONDITIONS: break;
  case DCAF_ATTRIBUTE_RULE_LIST: break;
  case DCAF_ATTRIBUTE_PERMISSION_LIST: break;
  case DCAF_ATTRIBUTE_LIST: break;
  case DCAF_CREDENTIAL_LIST: break;
  case DCAF_CREDENTIAL_STORE: break;
  case DCAF_ISSUER: break;
  }
  return dcaf_alloc_type_len(obj, len);
}

void
dcaf_free_type(dcaf_object_type obj, void *p) {
  /* FIXME: use static memory allocator on non-posix systems */
  switch (obj) {
  case DCAF_CONTEXT: FREE(obj, p); break;
  case DCAF_TICKET: FREE(obj, p); break;
  case DCAF_KEY: FREE(obj, p); break;
  case DCAF_AIF: FREE(obj, p); break;
  case DCAF_STRING: FREE(obj, p); break;
  case DCAF_VAR_STRING: FREE(obj, p); break;
  case DCAF_STRING_STR: FREE(obj, p); break;
  case DCAF_DEP_TICKET: FREE(obj, p); break;
  case DCAF_TRANSACTION: FREE(obj, p); break;
  case DCAF_NONCE: FREE(obj,p); break;
  case DCAF_TICKET_REQUEST: FREE(obj,p); break;
  case DCAF_ATTRIBUTE_REQUEST: FREE(obj,p); break;
  case DCAF_RULE_LIST: FREE(obj,p); break;
  case DCAF_AIF_PERMISSIONS: FREE(obj,p); break;
  case DCAF_ATTRIBUTE_CONDITIONS: FREE(obj,p); break;
  case DCAF_ATTRIBUTE_RULE_LIST: FREE(obj,p); break;
  case DCAF_ATTRIBUTE_PERMISSION_LIST: FREE(obj,p); break;
  case DCAF_ATTRIBUTE_LIST: FREE(obj,p); break;
  case DCAF_CREDENTIAL_LIST: FREE(obj,p); break;
  case DCAF_CREDENTIAL_STORE: FREE(obj,p); break;
  case DCAF_ISSUER: FREE(obj,p); break;
  default:
    ;
  }
}
#undef FREE
