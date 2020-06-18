/*
 * dcaf_base64.h -- UTF-8 encoder/decoder for DCAF
 *
 * Copyright (C) 2020 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef DCAF_UTF8_H
#define DCAF_UTF8_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Calculates the number of bytes the string @p src of length
 * @p srclen would take when encoded as UTF8. This function
 * considers only 8-bit values, i.e., code points between 0 and 255.
 *
 * @param src    The source to be encoded.
 * @param srclen The size of @p src in bytes.
 *
 * @return The number of bytes the UTF8-encoded string would take.
 */
size_t utf8_length(const uint8_t *src, size_t srclen);

/**
 * UTF8-encodes @p srclen bytes from @p src into the buffer @p
 * dst. @p *dstlen specifies the size of @p dst and is overwritten
 * with the number of bytes written. In case of error, the value of @p
 * *dstlen is undefined. This function only encodes 8-bit values, i.e.,
 * code points between 0 and 255.
 *
 * @param dst    The destination buffer to hold the base64-encoded input.
 * @param dstlen A pointer that is updated with the number of bytes
 *               that have actually been written. The initial value of
 *               of @p *dstlen must denote the maximum size of @p dst.
 * @param src    The source to be encoded.
 * @param srclen The size of @p src in bytes.
 *
 * @return True if @p src successfully has been encoded, false otherwise.
 *         In case of an error, the value written to @p *dstlen is undefined.
 */
bool uint8_to_utf8(char *dst, size_t *dstlen, const uint8_t *src, size_t srclen);

/**
 * UTF8-decodes @p srclen bytes from @p src into the buffer @p dst.
 * @p *dstlen specifies the size of @p dst and is overwritten with the
 * number of bytes written. In case of error, the value of @p *dstlen
 * is undefined. This function only decodes multibyte sequences that
 * lead to a single byte result, i.e., a code point between 0 and 255.
 * Input bytes larger than 195 hence will result in an error.
 *
 * @param dst    The destination buffer to hold the decoded data.
 * @param dstlen A pointer that is updated with the number of bytes
 *               that have actually been written. The initial value of
 *               of @p *dstlen must denote the maximum size of @p dst.
 * @param src    The source to be Base64-decoded.
 * @param srclen The size of @p src in bytes.
 *
 * @return True if @p src successfully has been decoded, false otherwise.
 *         In case of an error, the value written to @p *dstlen is undefined.
 */
bool utf8_to_uint8(uint8_t *dst, size_t *dstlen, const char *src, size_t srclen);

#endif /* DCAF_UTF8_H */
