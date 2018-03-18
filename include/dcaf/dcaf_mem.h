/*
 * dcaf_mem.h -- DCAF memory management
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_MEM_H_
#define _DCAF_MEM_H_ 1

typedef enum dcaf_object_type {
  DCAF_CONTEXT = 1,
  DCAF_AUTHZ,
  DCAF_TICKET,
  DCAF_KEY,
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
 * Releases the memory that has previously been allocated for @p obj.
 *
 * @param obj   The object type that was passed to dcaf_alloc_type().
 * @param p     A pointer returned by dcaf_alloc_type() or NULL.
 */
void dcaf_free_type(dcaf_object_type obj, void *p);

#endif /* _DCAF_MEM_H_ */
