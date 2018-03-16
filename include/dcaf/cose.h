/*
 * cose.h -- definitions from COSE (RFC 8152)
 *
 * Copyright (C) 2017-2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _COSE_H_
#define _COSE_H_ 1

#include <stdbool.h>
#include <stdint.h>

#include "dcaf/dcaf_debug.h"
#include "dcaf/cose_types.h"
#include "dcaf/dcaf_crypto.h"

struct cose_obj_t;
typedef struct cose_obj_t cose_obj_t;

/**
 * Result types for public COSE-related functions.
 */
typedef enum cose_result_t {
  COSE_OK,                      /**< operation was successful */
  COSE_OUT_OF_MEMORY_ERROR,     /**< insufficient memory for operation */
  COSE_PARSE_ERROR,             /**< the input could not be parsed */
  COSE_TYPE_ERROR,              /**< input contained an unexpected CBOR item */
  COSE_DECRYPT_ERROR,           /**< object could not be decrypted */
  COSE_NOT_SUPPORTED_ERROR,     /**< requested feature is not implemented */
} cose_result_t;

typedef enum cose_mode_t {
  COSE_MODE_ENCRYPT,
  COSE_MODE_DECRYPT,
  COSE_MODE_MAC,
} cose_mode_t;

/**
 * Parses the given @p data as COSE structure and stores the resulting data in
 * @p *result. This function returns COSE_OK on success, or an error value otherwise.
 * An object created by cose_parse() must be deleted with cose_obj_delete().
 *
 * @param data     The serialized CBOR data to parse as COSE structure.
 * @param data_len The length of @p data in bytes.
 * @param result   A result parameter that is set to a newly allocated cose_obj_t
 *                 structure on success. Undefined otherwise.
 * @return COSE_OK on success, or an error value otherwise.
 */
cose_result_t cose_parse(const uint8_t *data, size_t data_len, cose_obj_t **result);

/**
 * Deletes the given @p object and releases all storage that was allocated for this
 * object by cose_parse().
 *
 * @param object The COSE object to delete.
 */
void cose_obj_delete(cose_obj_t *object);

/**
 * Callback function to retrieve keying material to be used for the
 * operation specified by the mode parameter.
 */ 
typedef const dcaf_key_t *(*cose_key_callback_t)(const char *, size_t, cose_mode_t mode);

bool cose_encrypt0(const dcaf_crypto_param_t *params,
                   const uint8_t *message, size_t message_len,
                   const uint8_t *extaad, size_t extaad_len,
                   uint8_t *result, size_t *result_len);

cose_result_t cose_decrypt(cose_obj_t *obj,
                           uint8_t *external_aad, size_t external_aad_len,
                           uint8_t *data, size_t *data_len,
                           cose_key_callback_t cb);

/**
 * Outputs a readable representation of the COSE object @p obj
 * to the DCAF standard log function.
 *
 * @param level  The log level to use.
 * @param obj    The COSE object to show.
 */
void cose_show_object(dcaf_log_t level, const cose_obj_t *obj);
#endif /* _COSE_H_ */

