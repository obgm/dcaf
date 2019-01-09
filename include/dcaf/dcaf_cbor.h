/*
 * dcaf_cbor.h -- CBOR compatibility wrapper libdcaf
 *
 * Copyright (C) 2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_CBOR_H_
#define _DCAF_CBOR_H_ 1

#include <cn-cbor/cn-cbor.h>

/**
 * Initializes the global CBOR context if required. This function must
 * be called before any other DCAF CBOR wrapper function.
 */
void dcaf_cbor_init(void);

/* The following functions are wrappers for cn-cbor without the
 * conditional cbor_context structure. */

/**
 * Decode an array of CBOR bytes into structures.
 *
 * @param[in]  buf          The array of bytes to parse
 * @param[in]  len          The number of bytes in the array
ned)
 * @param[out] errp         Error, if NULL is returned
 * @return                  The parsed CBOR structure, or NULL on error
 */
cn_cbor *dcaf_cbor_decode(const uint8_t *buf,
                          size_t len,
                          cn_cbor_errback *errp);

/**
 * Get a value from a CBOR map that has the given string as a key.
 *
 * @param[in]  cb           The CBOR map
 * @param[in]  key          The string to look up in the map
 * @return                  The matching value, or NULL if the key is not found
 */
static inline cn_cbor *
dcaf_cbor_mapget_string(const cn_cbor* cb, const char* key) {
  return cn_cbor_mapget_string(cb, key);
}

/**
 * Get a value from a CBOR map that has the given integer as a key.
 *
 * @param[in]  cb           The CBOR map
 * @param[in]  key          The int to look up in the map
 * @return                  The matching value, or NULL if the key is not found
 */
static inline cn_cbor *
dcaf_cbor_mapget_int(const cn_cbor* cb, int key) {
  return cn_cbor_mapget_int(cb, key);
}

/**
 * Get the item with the given index from a CBOR array.
 *
 * @param[in]  cb           The CBOR map
 * @param[in]  idx          The array index
 * @return                  The matching value, or NULL if the index is invalid
 */
static inline cn_cbor *
dcaf_cbor_index(const cn_cbor* cb, unsigned int idx) {
  return cn_cbor_index(cb, idx);
}

/**
 * Free the given CBOR structure.
 * You MUST NOT try to free a cn_cbor structure with a parent (i.e., one
 * that is not a root in the tree).
 *
 * @param[in]  cb           The CBOR value to free.  May be NULL, or a root object.
 */
void dcaf_cbor_free(cn_cbor* cb);

/**
 * Write a CBOR value and all of the child values.
 *
 * @param[in]  buf        The buffer into which to write
 * @param[in]  buf_offset The offset (in bytes) from the beginning of the buffer
 *                        to start writing at
 * @param[in]  buf_size   The total length (in bytes) of the buffer
 * @param[in]  cb         [description]
 * @return                -1 on fail, or number of bytes written
 */
static inline ssize_t
dcaf_cbor_encoder_write(uint8_t *buf,
                        size_t buf_offset,
                        size_t buf_size,
                        const cn_cbor *cb) {
  return cn_cbor_encoder_write(buf, buf_offset, buf_size, cb);
}

/**
 * Create a CBOR map.
 *
 * @param[in]   CBOR_CONTEXT Allocation context (only if USE_CBOR_CONTEXT is defined)
 * @param[out]  errp         Error, if NULL is returned
 * @return                   The created map, or NULL on error
 */
cn_cbor* dcaf_cbor_map_create(cn_cbor_errback *errp);

/**
 * Create a CBOR byte string.  The data in the byte string is *not* owned
 * by the CBOR object, so it is not freed automatically.
 *
 * @param[in]   data         The data
 * @param[in]   len          The number of bytes of data
 * @param[out]  errp         Error, if NULL is returned
 * @return                   The created object, or NULL on error
 */
cn_cbor* dcaf_cbor_data_create(const uint8_t* data, int len,
                               cn_cbor_errback *errp);

/**
 * Create a CBOR UTF-8 string.  The data is not checked for UTF-8 correctness.
 * The data being stored in the string is *not* owned the CBOR object, so it is
 * not freed automatically.
 *
 * @note: Do NOT use this function with untrusted data.  It calls strlen, and
 * relies on proper NULL-termination.
 *
 * @param[in]   data         NULL-terminated UTF-8 string
 * @param[out]  errp         Error, if NULL is returned
 * @return                   The created object, or NULL on error
 */
cn_cbor* dcaf_cbor_string_create(const char* data, cn_cbor_errback *errp);

/**
 * Create a CBOR integer (either positive or negative).
 *
 * @param[in]   value    the value of the integer
 * @param[out]  errp         Error, if NULL is returned
 * @return                   The created object, or NULL on error
 */
cn_cbor* dcaf_cbor_int_create(int64_t value, cn_cbor_errback *errp);

/**
 * Create a CBOR float.
 *
 * @param[in]   value    the value of the float
 * @param[out]  errp         Error, if NULL is returned
 * @return                   The created object, or NULL on error
 */
cn_cbor *dcaf_cbor_float_create(float value, cn_cbor_errback *errp);

/**
 * Create a CBOR double.
 *
 * @param[in]   value    the value of the double
 * @param[out]  errp         Error, if NULL is returned
 * @return                   The created object, or NULL on error
 */
cn_cbor *dcaf_cbor_double_create(double value, cn_cbor_errback *errp);

/**
 * Put a CBOR object into a map with a CBOR object key.  Duplicate checks are NOT
 * currently performed.
 *
 * @param[in]   cb_map       The map to insert into
 * @param[in]   key          The key
 * @param[in]   cb_value     The value
 * @param[out]  errp         Error
 * @return                   True on success
 */
static inline bool
dcaf_cbor_map_put(cn_cbor* cb_map,
                  cn_cbor *cb_key, cn_cbor *cb_value,
                  cn_cbor_errback *errp) {
  return cn_cbor_map_put(cb_map, cb_key, cb_value, errp);
}

/**
 * Put a CBOR object into a map with an integer key.  Duplicate checks are NOT
 * currently performed.
 *
 * @param[in]   cb_map       The map to insert into
 * @param[in]   key          The integer key
 * @param[in]   cb_value     The value
 * @param[out]  errp         Error
 * @return                   True on success
 */
bool dcaf_cbor_mapput_int(cn_cbor* cb_map,
                          int64_t key, cn_cbor* cb_value,
                          cn_cbor_errback *errp);

/**
 * Put a CBOR object into a map with a string key.  Duplicate checks are NOT
 * currently performed.
 *
 * @note: do not call this routine with untrusted string data.  It calls
 * strlen, and requires a properly NULL-terminated key.
 *
 * @param[in]   cb_map       The map to insert into
 * @param[in]   key          The string key
 * @param[in]   cb_value     The value
 * @param[out]  errp         Error
 * @return                   True on success
 */
bool dcaf_cbor_mapput_string(cn_cbor* cb_map,
                             const char* key, cn_cbor* cb_value,
                             cn_cbor_errback *errp);

/**
 * Create a CBOR array
 *
 * @param[out]  errp         Error, if NULL is returned
 * @return                   The created object, or NULL on error
 */
cn_cbor* dcaf_cbor_array_create(cn_cbor_errback *errp);

/**
 * Append an item to the end of a CBOR array.
 *
 * @param[in]   cb_array  The array into which to insert
 * @param[in]   cb_value  The value to insert
 * @param[out]  errp      Error
 * @return                True on success
 */
static inline bool
dcaf_cbor_array_append(cn_cbor* cb_array,
                       cn_cbor* cb_value,
                       cn_cbor_errback *errp) {
  return cn_cbor_array_append(cb_array, cb_value, errp);
}

#endif /* _DCAF_CBOR_H_ */
