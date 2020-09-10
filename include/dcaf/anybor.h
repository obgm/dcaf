/*
 * anybor.h -- small CBOR encoder/decoder for libdcaf
 *
 * Copyright (C) 2020 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _ANYBOR_H_
#define _ANYBOR_H_ 1

struct abor_encoder_t;
typedef struct abor_encoder_t abor_encoder_t;

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** The known major types */
typedef enum {
              ABOR_UINT = 0,
              ABOR_NEGINT,
              ABOR_BSTR,
              ABOR_TSTR,
              ABOR_ARRAY,
              ABOR_MAP,
              ABOR_TAG,
              ABOR_SPECIAL,
              ABOR_INVALID = 99
} abor_type;

/************************************************************************
 * Encoder functions
 ************************************************************************/

bool abor_write_tlv(abor_encoder_t *abc, uint8_t type, size_t num);

bool abor_write_array(abor_encoder_t *abc, size_t num);

bool abor_write_map(abor_encoder_t *abc, size_t num);

bool abor_write_uint(abor_encoder_t *abc, uint64_t num);

bool abor_write_int(abor_encoder_t *abc, int num);

bool abor_write_bytes(abor_encoder_t *abc, const uint8_t *data, size_t length);

bool abor_write_text(abor_encoder_t *abc, const char *data, size_t length);

bool abor_write_string(abor_encoder_t *abc, const char *data);

bool abor_write_bool(abor_encoder_t *abc, bool b);

bool abor_write_null(abor_encoder_t *abc);

bool abor_write_undefined(abor_encoder_t *abc);

bool abor_write_tag(abor_encoder_t *abc, uint64_t tag);

abor_encoder_t *abor_encode_start(uint8_t *buf, size_t buflen);

size_t abor_encode_finish(abor_encoder_t *abc);

/************************************************************************
 * Decoder functions
 ************************************************************************/

/**
 * Returns the major type of the CBOR item that starts at @p data.
 * This function returns ABOR_INVALID if @p abd does not point to a
 * valid CBOR type.
 */
abor_type abor_get_major_type(const uint8_t *data);

typedef struct abor_decoder_t abor_decoder_t;

/**
 * Returns the major type of the next CBOR item in @p abd.  This
 * function returns ABOR_INVALID if @p abd does not point to a valid
 * CBOR type.
 */
abor_type abor_get_type(const abor_decoder_t *abd);

/**
 * Creates a deep copy of the CBOR item that @src points to into the
 * encoding buffer pointed to by @p dst. This function returns true if
 * the @p src was decoded properly and the result was written
 * successfully into @p dst.
 *
 * @param src The CBOR item to copy.
 * @param dst The output buffer to write the copy.
 * @return true if the item was successfully copied from @p src into
 * @p dst.
 */
bool abor_copy_item(const abor_decoder_t *src, abor_encoder_t *dst);

/**
 * Copies @p count bytes starting at @p src into the encoding buffer
 * pointed to by @p dst. This function returns true if all bytes have
 * been successfully copied into @p dst.
 *
 * @param src   The beginning of the byte sequence to copy.
 * @param count The actual size of @p src.
 * @param dst The output buffer to write the copy.
 * @return true if successfully copied @p count bytes from @p src into
 * @p dst.
 */
bool abor_copy_raw(const uint8_t *src, size_t count, abor_encoder_t *dst);

/**
 * Associates a new decoder object for decoding the data at @p buf and
 * the maximum length of @p buflen. The contents of @p buf must remain
 * valid as long as functions are called that operate on the created
 * abor_decoder_t object (i.e., usually, until abor_decode_finish() is
 * called). If ABOR_STATIC_MAPGET_NUM_ITEMS is defined, this decoder
 * object will be static as well. This means that only one encoder
 * created by abor_decode_start() can exist at a time. (And
 * ABOR_STATIC_MAPGET_NUM_ITEMS decoders that have been created by the
 * mapget functions.
 *
 * @param buf    The data to decode.
 * @param buflen The maximum length of @p buf.
 * @return A new decoder object for @p buf. This object must be
 * released with abor_decode_finish().
 */
abor_decoder_t *abor_decode_start(const uint8_t *buf, size_t buflen);

/**
 * Releases all resources that have been allocated for @p abd.
 */
void abor_decode_finish(abor_decoder_t *abd);

/**
 * Returns true if the current item pointed to by @p abd is of the
 * given @p type.
 */
bool abor_check_type(const abor_decoder_t *abd, abor_type type);

/**
 * Retrieves the value component of the map entry with the given
 * @p label. If @p abd does not point to a map, @c NULL is returned.
 * This function returns a new abor_decoder_t object for the first
 * element with label @p label, or @c NULL if not found. The
 * returned object must be released with abor_decode_finish().
 *
 * If ABOR_STATIC_MAPGET_NUM_ITEMS is defined, no more than
 * ABOR_STATIC_MAPGET_NUM_ITEMS mapget calls are possible without
 * overwriting previous entries.
 *
 * @param abd   The current decoder context. Must point to a CBOR map.
 * @param label The label of the map entry to search.
 * @return A new abor_decoder_t object pointing to the value if
 *         @p label was found, @c NULL otherwise. This object must
 *         be released with abor_decode_finish().
 */
abor_decoder_t *abor_mapget_int(const abor_decoder_t *abd, int label);

bool abor_get_uint(abor_decoder_t *abd, uint64_t *num);
bool abor_get_int(abor_decoder_t *abd, int *val);

bool abor_consume_tag(abor_decoder_t *abd, uint32_t tag);

size_t abor_get_sequence_length(const abor_decoder_t *abd);
const uint8_t *abor_get_bytes(const abor_decoder_t *abd);
const char *abor_get_text(const abor_decoder_t *abd);

bool abor_copy_bytes(const abor_decoder_t *abd, uint8_t *dst, size_t *dstlen);

bool abor_copy_text(const abor_decoder_t *abd, uint8_t *dst, size_t *dstlen);

/************************************************************************
 * Iterator
 ************************************************************************/

struct abor_iterator_t;
typedef struct abor_iterator_t abor_iterator_t;

abor_iterator_t *abor_iterate_start(const abor_decoder_t *abd);

abor_decoder_t *abor_iterate_get(const abor_iterator_t *it);

bool abor_iterate_next(abor_iterator_t *it);

void abor_iterate_finish(const abor_iterator_t *it);

/************************************************************************
 * Type check functions
 ************************************************************************/

bool abor_is_null(const abor_decoder_t *abd);


/************************************************************************
 * Functions for internal use
 ************************************************************************/

/**
 * Returns the current parse position from @p abd or NULL if invalid.
 * When reading from this pointer it must be ensured that not more
 * than abor_decode_get_max_length(abd) bytes are read.
 */
const uint8_t *abor_decode_get_raw_pointer(const abor_decoder_t *abd);

/**
 * Returns the maximum length of bytes in the decoder buffer
 * associated to @p abd.
 */
size_t
abor_decode_get_max_length(const abor_decoder_t *abd);

/**
 * Returns the encoded size of the CBOR object pointed to by @p abd,
 * or 0 if invalid.
 */
size_t abor_decode_get_size(const abor_decoder_t *abd);

#endif /* _ANYBOR_H_ */
