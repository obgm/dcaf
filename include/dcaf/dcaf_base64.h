/*
 * dcaf_base64.h -- base64 wrapper for DCAF
 *
 * Copyright (C) 2020 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef DCAF_BASE64_H
#define DCAF_BASE64_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Base64-encodes @p srclen bytes from @p src into the buffer @p
 * dst. @p *dstlen specifies the size of @p dst and is overwritten
 * with the number of bytes written. In case of error, the value of @p
 * *dstlen is undefined.
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
bool dcaf_base64_encode(uint8_t *dst, size_t *dstlen, const uint8_t *src, size_t srclen);

/**
 * Base64-decodes @p srclen bytes from @p src into the buffer @p
 * dst. @p *dstlen specifies the size of @p dst and is overwritten
 * with the number of bytes written. In case of error, the value of @p
 * *dstlen is undefined.
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
bool dcaf_base64_decode(uint8_t *dst, size_t *dstlen, const uint8_t *src, size_t srclen);

#endif /* DCAF_BASE64_H */
