/*
 * aif.h -- authorization information format
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _AIF_H_
#define _AIF_H_ 1

#include <stdint.h>
#include <cn-cbor/cn-cbor.h>

#include "dcaf/dcaf.h"

#define DCAF_MAX_RESOURCE_LEN 32
typedef struct dcaf_aif_permission_t {
  uint8_t resource[DCAF_MAX_RESOURCE_LEN];
  size_t resource_len;
  uint32_t methods;
} dcaf_aif_permission_t;

/** A list of DCAF resources */
typedef struct dcaf_aif_t {
  struct dcaf_aif_t *next;
  dcaf_aif_permission_t perm;
} dcaf_aif_t;

/**
 * Parses @p cbor string into the AIF format and returns a newly
 * created dcaf_aif_t list representing this information on
 * success. This function returns DCAF_OK on success or an error code
 * on error.
 *
 * @param cbor   The CBOR input to parse.
 * @param result An output parameter that will be set to a new
 *               list of AIF structures on success, or NULL otherwise.
 *               The memory allocated for the created dcaf_aif_t
 *               objects must be released by dcaf_delete_aif().
 *               As the information represented by @p result points
 *               to @p cbor it becomes invalid when @p cbor is
 *               released.
 *
 * @return       DCAF_OK on success, an error code otherwise.
 */
dcaf_result_t dcaf_aif_parse_string(const cn_cbor *cbor, dcaf_aif_t **result);

/**
 * Parses @p cbor into the AIF format and returns a newly created
 * dcaf_aif_t list representing this information on success. This
 * function returns DCAF_OK on success or an error code on error.
 *
 * @param cbor   The CBOR input to parse.
 * @param result An output parameter that will be set to a new
 *               list of AIF structures on success, or NULL otherwise.
 *               The memory allocated for the created dcaf_aif_t
 *               objects must be released by dcaf_delete_aif().
 *               As the information represented by @p result points
 *               to @p cbor it becomes invalid when @p cbor is
 *               released.
 *
 * @return       DCAF_OK on success, an error code otherwise.
 */
dcaf_result_t dcaf_aif_parse(const cn_cbor *cbor, dcaf_aif_t **result);

/**
 * Creates a CBOR representation of @p aif. This function returns a
 * newly created CBOR array if at least one AIF item was created.  In
 * case of an error, NULL is returned. The CBOR array will point into
 * the @p aif data and thus will get invalid when @p aif ceases to
 * exist.
 *
 * @param aif   The AIF object to convert into CBOR.
 *
 * @return A newly created CBOR array on success, or NULL on error.
 */
cn_cbor *dcaf_aif_to_cbor(const dcaf_aif_t *aif);

/**
 * Releases the storage for @p aif and all following elements in the
 * list.
 */
void dcaf_delete_aif(dcaf_aif_t *aif);

#endif /* _AIF_H_ */

