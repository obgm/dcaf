/*
 * dcaf_base64.c -- base64 wrapper for DCAF
 *
 * Copyright (C) 2020 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <assert.h>
#include <stdio.h>

#include "dcaf/dcaf_base64.h"

#ifdef COAP_DTLS_MBEDTLS
#include <mbedtls/base64.h>
bool dcaf_base64_encode(uint8_t *dst, size_t *dstlen,
                        const uint8_t *src, size_t srclen) {
  size_t olen;
  if (mbedtls_base64_encode((unsigned char *)dst, *dstlen, &olen,
                            (const unsigned char *)src, srclen) != 0) {
    return false;
  }
  *dstlen = olen;
  return true;
}

bool dcaf_base64_decode(uint8_t *dst, size_t *dstlen,
                        const uint8_t *src, size_t srclen) {
  size_t olen;
  if (mbedtls_base64_decode((unsigned char *)dst, *dstlen, &olen,
                            (const unsigned char *)src, srclen) != 0) {
    return false;
  }
  *dstlen = olen;
  return true;
}
#elif defined(RIOT_VERSION)
#include <base64.h>

bool dcaf_base64_encode(uint8_t *dst, size_t *dstlen,
                        const uint8_t *src, size_t srclen) {
  return base64_encode(src, srclen (unsigned char *)dst, *dstlen)
    == BASE64_SUCCESS;
}

bool dcaf_base64_decode(uint8_t *dst, size_t *dstlen,
                        const uint8_t *src, size_t srclen) {
  return base64_decode(src, srclen (unsigned char *)dst, *dstlen)
    == BASE64_SUCCESS;
}
#else /* !COAP_DTLS_MBEDTLS && !RIOT_VERSION */

static const char alphabet[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static int find_code(uint8_t c) {
  uint8_t n;
  for (n = 0; n < sizeof(alphabet) && alphabet[n] != c; n++)
    ;
  return n < sizeof(alphabet) ? n : -1;
}

static const char pad = '=';

bool dcaf_base64_encode(uint8_t *dst, size_t *dstlen,
                        const uint8_t *src, size_t srclen) {
  unsigned int state = 0;
  uint8_t *p = dst;
  uint32_t buf = 0;
  const uint8_t mask = 0x3f;

  while(srclen-- && (p < (dst + *dstlen))) {
    buf <<= 8;
    buf += *src;

    /* TODO: length check for dst buffer */
    state = (state + 1) % 3;
    if (state == 0) {           // output accumulated bit group
      *p++ = alphabet[(buf >> 18) & mask];
      *p++ = alphabet[(buf >> 12) & mask];
      *p++ = alphabet[(buf >> 6) & mask];
      *p++ = alphabet[buf & mask];
      buf = 0;
    }
    src++;
  }

  // output remaining characters, if any
  switch (state) {
  case 2: {
    buf <<= 8;
    *p++ = alphabet[(buf >> 18) & mask];
    *p++ = alphabet[(buf >> 12) & mask];
    *p++ = alphabet[(buf >> 6) & mask];
    *p++ = pad;
    break;
  }
  case 1: {
    buf <<= 16;
    *p++ = alphabet[(buf >> 18) & mask];
    *p++ = alphabet[(buf >> 12) & mask];
    *p++ = pad;
    *p++ = pad;
    break;
  }
  default:
    ;
  }
  *dstlen = p - dst;
  return true;
}

bool dcaf_base64_decode(uint8_t *dst, size_t *dstlen,
                        const uint8_t *src, size_t srclen) {
  unsigned int state = 0;
  uint8_t buf = 0;
  int code;
  uint8_t bits;
  uint8_t *p = dst;

  while (srclen-- && (p < (dst + *dstlen))) {
    if (*src == pad) {    // special treatment for padding character
      if (state > 1) {
        *p = buf;
      }
      *dstlen = p - dst;
      return true;
    }
    code = find_code(*src);

    // ignore unknown characters
    if (code == -1)
      continue;

    bits = code;
    switch (state) {
    case 0: // handle first byte
      buf = bits << 2;
      break;
    case 1: // handle second byte
      (*p++) = buf | (bits >> 4);
      buf = bits << 4;
      break;
    case 2: // handle third byte
      (*p++) = buf | (bits >> 2);
      buf = bits << 6;
      break;
    case 3: // handle fourth byte
      (*p++) = buf | (bits & 0x3f);
      buf = 0;
      break;
    default:
      assert(false); /* never reached */
    }

    /* advance state (modulo 4) and src */
    state = (state + 1) % 4;
    src++;
  }
  *dstlen = p - dst;
  return true;
}

#endif /* !COAP_DTLS_MBEDTLS && !RIOT_VERSION */
