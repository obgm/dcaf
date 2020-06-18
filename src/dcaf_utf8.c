/*
 * dcaf_base64.c -- UTF-8 encoder/decoder for DCAF
 *
 * Copyright (C) 2020 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include "dcaf/dcaf_utf8.h"

#define CHECK_PTR(Current, End, Count)                  \
  if ((End) < ((Current) + (Count))) { goto finish; }

size_t utf8_length(const uint8_t *src, size_t srclen) {
  size_t n = srclen;
  while (srclen--) {
    /* traverse string and add 1 for each character above 127 */
    if (*src++ > 127)
      n++;
  }
  return n;
}

bool uint8_to_utf8(char *dst, size_t *dstlen,
                   const uint8_t *src, size_t srclen) {
  char *p = dst;
  bool ok = false;
  while (srclen-- && (p < dst + *dstlen)) {
    uint8_t c = *src++;
    if (c <= 127)
      *p++ = c;
    else {
      CHECK_PTR(p, dst + *dstlen, 2);
      *p++ = 0xc0 + (c >> 6);
      *p++ = 0x80 + (c & 0x3f);
    }
  }
  *dstlen = p - dst;
  ok = true;
 finish:
  return ok;
}

bool utf8_to_uint8(uint8_t *dst, size_t *dstlen,
                   const char *src, size_t srclen) {
  uint8_t *p = dst;
  bool ok = false;
  while (srclen-- && (p < dst + *dstlen)) {
    unsigned char c = *src++;
    if (c <= 127)
      *p++ = c;
    else if (c <= 195) {        /* only up to 8 bits supported */
      CHECK_PTR(src, src + srclen, 1);
      *p = (c << 6);
      c = *src++;
      if ((c >> 6) != 2)        /* is the next byte valid UTF-8? */
        goto finish;
      *p += (c & 0x3f);
      p++;
      srclen--;
    } else {                   /* wide characters are not supported */
      goto finish;
    }
  }
  *dstlen = p - dst;
  ok = true;
 finish:
  return ok;
}
