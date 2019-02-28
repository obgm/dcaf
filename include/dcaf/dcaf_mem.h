/*
 * dcaf_mem.h -- DCAF memory management
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 *
 * Extended by Sara Stadler 2018/2019.
 */

#ifndef _DCAF_MEM_H_
#define _DCAF_MEM_H_ 1

typedef enum dcaf_object_type {
  DCAF_CONTEXT = 1,
  DCAF_TICKET,
  DCAF_KEY,
  DCAF_AIF,  
  DCAF_STRING,
  DCAF_VAR_STRING,
  DCAF_STRING_STR,
  DCAF_DEP_TICKET,
  DCAF_TRANSACTION,
  DCAF_NONCE,
  DCAF_TICKET_REQUEST,
  DCAF_ATTRIBUTE_REQUEST,
  DCAF_RULE_LIST,
  DCAF_AIF_PERMISSIONS,
  DCAF_ATTRIBUTE_CONDITIONS,
  DCAF_ATTRIBUTE_RULE_LIST,
  DCAF_ATTRIBUTE_PERMISSION_LIST,
  DCAF_ATTRIBUTE_LIST,
  DCAF_CREDENTIAL_LIST,
  DCAF_CREDENTIAL_STORE,
  DCAF_ISSUER,
} dcaf_object_type;

/**
 * Allocates memory for the object type @p obj. This function returns
 * a pointer to a new object of type @p obj that must be released with
 * dcaf_free_type() or NULL on error.
 *
 * @param obj  The object type to allocate.
 *
 * @return A pointer to a new object of type @p obj or NULL on error.
 */
void *dcaf_alloc_type(dcaf_object_type obj);

/**
 * Allocates memory for the object type @p obj with @p len bytes
 * additional data. Depending on the requested object type, there may
 * be upper bounds defined when using static memory allocation.  This
 * function returns a pointer to a new object of type @p obj that must
 * be released with dcaf_free_type() or NULL on error.
 *
 * @param obj  The object type to allocate.
 * @param len  The number of additional bytes to allocate.
 *
 * @return A pointer to a new object of type @p obj or NULL on error.
 */
void *dcaf_alloc_type_len(dcaf_object_type obj, size_t len);

/**
 * Releases the memory that has previously been allocated for @p obj.
 *
 * @param obj   The object type that was passed to dcaf_alloc_type().
 * @param p     A pointer returned by dcaf_alloc_type() or NULL.
 */
void dcaf_free_type(dcaf_object_type obj, void *p);

#endif /* _DCAF_MEM_H_ */
