/*
 * anybor.c -- small CBOR encoder/decoder for libdcaf
 *
 * Copyright (C) 2020 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <assert.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

#include "dcaf/anybor.h"

static size_t
write_tlv(uint8_t *buf, size_t maxlen, uint8_t mtype, uint64_t num) {
#define CHECK_REMAINING(Sz, Needed) if ((Sz) < (Needed)) {  goto error; }
#define MAJOR(Type) (((Type) & 0x7) << 5)
  size_t written = 0;
  if (num <= 23) {
    CHECK_REMAINING(maxlen, 1);
    buf[0] = MAJOR(mtype) + num;
    written = 1;
  } else if (num <= UINT8_MAX) {
    CHECK_REMAINING(maxlen, 2);
    buf[0] = MAJOR(mtype) + 24;
    buf[1] = num & 0xff;
    written = 2;
  } else if (num <= UINT16_MAX) {
    CHECK_REMAINING(maxlen, 3);
    buf[0] = MAJOR(mtype) + 25;
    buf[1] = (num >> 8) & 0xff;
    buf[2] = num & 0xff;
    written = 3;
  } else if (num <= UINT32_MAX) {
    CHECK_REMAINING(maxlen, 5);
    buf[0] = MAJOR(mtype) + 26;
    buf[1] = (num >> 24) & 0xff;
    buf[2] = (num >> 16) & 0xff;
    buf[3] = (num >> 8) & 0xff;
    buf[4] = num & 0xff;
    written = 5;
  } else /* uint64_t */ {
    CHECK_REMAINING(maxlen, 9);
    buf[0] = MAJOR(mtype) + 27;
    buf[1] = (num >> 56) & 0xff;
    buf[2] = (num >> 48) & 0xff;
    buf[3] = (num >> 40) & 0xff;
    buf[4] = (num >> 32) & 0xff;
    buf[5] = (num >> 24) & 0xff;
    buf[6] = (num >> 16) & 0xff;
    buf[7] = (num >> 8) & 0xff;
    buf[8] = num & 0xff;
    written = 9;
  }
 error:
  return written;
}

struct abor_encoder_t { 
  uint8_t *data;
  uint8_t *pos;
  size_t avail;
};

bool
abor_write_tlv(abor_encoder_t *abc, uint8_t type, size_t num) {
  size_t written;
  assert(abc);
  written = write_tlv(abc->pos, abc->avail, type, num);
  assert(written <= abc->avail);
  if (written) {
    abc->pos += written;
    abc->avail -= written;
  }
  return written > 0;
}

bool
abor_write_array(abor_encoder_t *abc, size_t num) {
  const uint8_t mt_array = 4;
  return abor_write_tlv(abc, mt_array, num);
}

bool
abor_write_map(abor_encoder_t *abc, size_t num) {
  const uint8_t mt_map = 5;
  return abor_write_tlv(abc, mt_map, num);
}

bool
abor_write_uint(abor_encoder_t *abc, uint64_t num) {
  const uint8_t mt_uint = 0;
  return abor_write_tlv(abc, mt_uint, num);
}

bool
abor_write_int(abor_encoder_t *abc, int num) {
  const uint8_t mt_uint = 0;
  const uint8_t mt_int = 1;

  if (num < 0)
    return abor_write_tlv(abc, mt_int, (uint64_t)~num);
  else
    return abor_write_tlv(abc, mt_uint, (uint64_t)num);
}

static bool
write_tlv_sequence(abor_encoder_t *abc, uint8_t type,
                   const uint8_t *data, size_t length) {
  uint8_t *oldpos = abc->pos;
  size_t oldavail = abc->avail;

  if (!abor_write_tlv(abc, type, (uint64_t)length))
    return false;

  /* Check if there is sufficient space in the write buffer and
   * rollback if not. */
  if (abc->avail < length) {
    abc->pos = oldpos;
    abc->avail = oldavail;
    return false;
  }

  /* copy string into write buffer and update encoder context */
  if (length > 0) {
    memcpy(abc->pos, data, length);
    abc->pos += length;
    abc->avail -= length;
  }
  return true;
}

bool
abor_write_bytes(abor_encoder_t *abc, const uint8_t *data, size_t length) {
  const uint8_t mt_bstr = 2;
  return write_tlv_sequence(abc, mt_bstr, data, (uint64_t)length);
}

bool
abor_write_text(abor_encoder_t *abc, const char *data, size_t length) {
  const uint8_t mt_tstr = 3;
  return write_tlv_sequence(abc, mt_tstr, (uint8_t *)data, (uint64_t)length);
}

bool
abor_write_string(abor_encoder_t *abc, const char *data) {
  return abor_write_text(abc, data, strlen(data));
}

bool
abor_write_bool(abor_encoder_t *abc, bool b) {
  const uint8_t mt_other = 7;
  return abor_write_tlv(abc, mt_other, b ? 21 : 20);
}

bool
abor_write_null(abor_encoder_t *abc) {
  const uint8_t mt_other = 7;
  return abor_write_tlv(abc, mt_other, 22);
}

bool
abor_write_undefined(abor_encoder_t *abc) {
  const uint8_t mt_other = 7;
  return abor_write_tlv(abc, mt_other, 23);
}

bool
abor_write_tag(abor_encoder_t *abc, uint64_t tag) {
  const uint8_t mt_tag = 6;
  return abor_write_tlv(abc, mt_tag, tag);
}

abor_encoder_t *
abor_encode_start(uint8_t *buf, size_t buflen) {
  static abor_encoder_t abc;
  if (!buf)
    return NULL;

  abc.data = buf;
  abc.pos = buf;
  abc.avail = buflen;
  return &abc;
}

size_t
abor_encode_finish(abor_encoder_t *abc) {
  assert(abc);
  return abc->pos - abc->data;
}

/************************************************************************/

struct abor_decoder_t { 
  const uint8_t *data;
  const uint8_t *pos;
  size_t len;
};

#define abor_alloc(Size) malloc(Size)

/**
 * Storage release function. This function must be able to handle
 * calls to abor_free(NULL).
 */
#define abor_free(Ptr) free(Ptr)

#define ABOR_STATIC_MAPGET_NUM_ITEMS  (4U)
#ifdef ABOR_STATIC_MAPGET_NUM_ITEMS
static abor_decoder_t static_item[ABOR_STATIC_MAPGET_NUM_ITEMS];
static size_t current_item = ABOR_STATIC_MAPGET_NUM_ITEMS - 1;
static abor_decoder_t *
new_decoder(void) {
  current_item = (current_item + 1) % ABOR_STATIC_MAPGET_NUM_ITEMS;
  return &static_item[current_item];
}

static void
free_decoder(abor_decoder_t *abd) {
  (void)abd;
  /* This must be a no-op because not only decoders allocated by
   * new_decoder are released here but also the static decoder from
   * abor_decode_start(). */
}
#else /* !ABOR_STATIC_MAPGET_NUM_ITEMS */
static abor_decoder_t *
new_decoder(void) {
  return (abor_decoder_t *)abor_alloc(sizeof(abor_decoder_t));
}

static void
free_decoder(abor_decoder_t *abd) {
  /* Free any decoder that has been allocated with abor_alloc() */
  abor_free(abd);
}
#endif /* ABOR_STATIC_MAPGET_NUM_ITEMS */

abor_decoder_t *
abor_decode_start(const uint8_t *buf, size_t buflen) {
  abor_decoder_t *abd;
#ifdef ABOR_STATIC_MAPGET_NUM_ITEMS
  static abor_decoder_t abd_;
  abd = &abd_;
#else /* ABOR_STATIC_MAPGET_NUM_ITEMS */
  abd = (abor_decoder_t *)abor_alloc(sizeof(abor_decoder_t));
  if (!abd)
    return NULL;
#endif /* ABOR_STATIC_MAPGET_NUM_ITEMS */
  abd->data = buf;
  abd->pos = buf;
  abd->len = buflen;
  return abd;
}

void
abor_decode_finish(abor_decoder_t *abd) {
  free_decoder(abd);
}

abor_type
abor_get_major_type(const uint8_t *data) {
  uint8_t mt;
  mt = (abor_type)(*data >> 5);
  return mt <= ABOR_SPECIAL ? mt : ABOR_INVALID;
}

abor_type
abor_get_type(const abor_decoder_t *abd) {
  assert(abd);
  if (abd && abd->pos && (abd->len > 0))
    return abor_get_major_type(abd->pos);
  else
    return ABOR_INVALID;
}

bool
abor_check_type(const abor_decoder_t *abd, abor_type type) {
  if (abd && abd->pos && (abd->len > 0))
    return abor_get_major_type(abd->pos) == type;
  else
    return false;
}

bool
abor_is_null(const abor_decoder_t *abd) {
  if (abd && abd->pos && (abd->len > 0))
    return *abd->pos == (ABOR_SPECIAL << 5) + 22;
  else
    return false;
}

static size_t
parse_number(const uint8_t *buf, size_t maxlen, uint64_t *num) {
  uint8_t c;
  size_t parsed = 0;
  CHECK_REMAINING(maxlen, 1);
  c = buf[0] & 0x1f;

  if (c <= 23) {
    *num = c;
    parsed = 1;
  } else if (c == 24) {
    CHECK_REMAINING(maxlen, 2);
    *num = buf[1];
    parsed = 2;
  } else if (c == 25) {
    CHECK_REMAINING(maxlen, 3);
    *num = (buf[1] << 8) + buf[2];
    parsed = 3;
  } else if (c == 26) {
    CHECK_REMAINING(maxlen, 5);
    *num = (buf[1] << 24) + (buf[2] << 16) + (buf[3] << 8) + buf[4];
    parsed = 5;
  } else if (c == 27) {
    CHECK_REMAINING(maxlen, 9);
    *num = ((uint64_t)buf[1] << 56)
      + ((uint64_t)buf[2] << 48)
      + ((uint64_t)buf[3] << 40)
      + ((uint64_t)buf[4] << 32)
      + (buf[5] << 24)
      + (buf[6] << 16)
      + (buf[7] << 8)
      + buf[8];
    parsed = 9;
  }
 error:
  return parsed;
}

static size_t
skip_item(const uint8_t *buf, size_t maxlen) {
  uint64_t num;
  size_t parsed;
  abor_type mt;
  const uint8_t *pos = buf;

  if (maxlen < 1)
    return 0;
  mt = abor_get_major_type(pos);
  parsed = parse_number(pos, maxlen, &num);
  if (!parsed)            /* error */
    return 0;
  pos += parsed;
  maxlen -= parsed;

  if (mt == ABOR_BSTR || mt == ABOR_TSTR) {     /* sequences */
    if (maxlen < num)      /* error */
      return 0;
    /* skip contents of text string or byte string */
    return pos + num - buf;
  }

  if (mt == ABOR_ARRAY) {                /* array */
    /* num contains the number of elements in the array */
    while (num--) {
      parsed = skip_item(pos, maxlen);
      if (!parsed)
        return 0;
      pos += parsed;
      maxlen -= parsed;
    }
    return pos - buf;
  }

  if (mt == ABOR_MAP) {                /* map */
    /* num contains the number of pairs in the map */
    while (num--) {
      parsed = skip_item(pos, maxlen);
      if (!parsed)
        return 0;
      pos += parsed;
      maxlen -= parsed;

      parsed = skip_item(pos, maxlen);
      if (!parsed)
        return 0;
      pos += parsed;
      maxlen -= parsed;
    }
    return pos - buf;
  }

  if (mt == ABOR_TAG) {                /* tagged item */
    /* skip tag and subsequent item */
    parsed = skip_item(pos, maxlen);
    if (!parsed)
      return 0;
    return pos + parsed - buf;
  }

  return pos - buf;
}

bool
abor_copy_raw(const uint8_t *src, size_t count, abor_encoder_t *dst) {
  size_t len;
  len = skip_item(src, count);
  if (dst->avail < len)     /* also true for len == 0 */
    return false;
  memcpy(dst->pos, src, len);
  dst->pos += len;
  dst->avail -= len;
  return true;
}

bool
abor_copy_item(const abor_decoder_t *src, abor_encoder_t *dst) {
  size_t len;
  len = skip_item(src->pos, src->len);
  return abor_copy_raw(src->pos, len, dst);
}

abor_decoder_t *
abor_mapget_int(const abor_decoder_t *abd, int label) {
  uint64_t num;
  size_t parsed;
  abor_decoder_t *found = NULL;
  if (abor_get_major_type(abd->pos) != ABOR_MAP)
    return NULL;

  /* Work on local copies of the variable fields in the abor
   * decoder. */
  parsed = parse_number(abd->pos, abd->len, &num);
  assert(parsed <= abd->len);
  if (parsed) {
    const uint8_t *pos = abd->pos + parsed;
    size_t len = abd->len - parsed;
    while (num-- && len) {
      abor_type mt = abor_get_major_type(pos);
      uint64_t value;
      if (mt == ABOR_UINT || mt == ABOR_NEGINT) { /* numeric? */
        parsed = parse_number(pos, len, &value);
        if (!parsed)            /* error */
          return NULL;
        pos += parsed;
        len -= parsed;
        if (label >= 0) {
          if (mt == ABOR_UINT && value == (unsigned int)label) { /* found */
            found = new_decoder();
            if (found) {
              found->data = abd->data;
              found->pos = pos;
              found->len = len;
            }
            break;
          }
        } else {                           /* label < 0 */
          if (mt == ABOR_NEGINT && value == (unsigned int)~label) { /* found */
            found = new_decoder();
            if (found) {
              found->data = abd->data;
              found->pos = pos;
              found->len = len;
            }
            break;
          }
        }
      } else {
        parsed = skip_item(pos, len); /* skip label */
        if (!parsed)
          return NULL;
        pos += parsed;
        len -= parsed;
      }

      /* skip contents */
      parsed = skip_item(pos, len); /* skip label */
      if (!parsed)
        return NULL;
      pos += parsed;
      len -= parsed;
    }
  }
  return found;
}

bool
abor_get_uint(abor_decoder_t *abd, uint64_t *num) {
  return abd && (abd->len > 0)
    && (abor_get_major_type(abd->pos) == ABOR_UINT)
    && (parse_number(abd->pos, abd->len, num) > 0);
}

bool
abor_get_int(abor_decoder_t *abd, int *val) {
  uint64_t num;
  abor_type mt;
  bool ok;

  *val = 0;
  if (!abd || !abd->pos || (abd->len == 0))
    return false;

  mt = abor_get_major_type(abd->pos);
  ok = parse_number(abd->pos, abd->len, &num) > 0;
  if (ok) {
    if (mt == ABOR_UINT) {
      *val = num & INT_MAX;
      ok = ((unsigned int)*val == num);
    } else if (mt == ABOR_NEGINT) {
      *val = (unsigned int)~num;
      /* TODO: set ok to false in case of overflow/underflow */
    }
  }

  return ok;
}

bool
abor_consume_tag(abor_decoder_t *abd, uint32_t tag) {
  if (abd && (abor_get_major_type(abd->pos) == ABOR_TAG)) {
    uint64_t num;
    size_t parsed;
    parsed = parse_number(abd->pos, abd->len, &num);
    if (parsed && (num == tag)) {
      abd->pos += parsed;
      abd->len -= parsed;
      return true;
    }
  }
  return false;
}

static bool
tlv_copy_sequence(const uint8_t *src, size_t srclen,
 uint8_t *dst, size_t *dstlen) {
  uint64_t bytes_to_read;
  size_t parsed;
  parsed = parse_number(src, srclen, &bytes_to_read);
  if (!parsed || (srclen - parsed < bytes_to_read)
      || (*dstlen < bytes_to_read))
    return false;

  memcpy(dst, src + parsed, bytes_to_read);
  *dstlen = bytes_to_read;
  return true;
}

bool
abor_copy_bytes(const abor_decoder_t *abd, uint8_t *dst, size_t *dstlen) {
  assert(abd);
  return (abd->len > 0) && (abor_get_major_type(abd->pos) == ABOR_BSTR)
    && tlv_copy_sequence(abd->pos, abd->len, dst, dstlen);
}

bool
abor_copy_text(const abor_decoder_t *abd, uint8_t *dst, size_t *dstlen) {
  assert(abd);
  return (abd->len > 0) && (abor_get_major_type(abd->pos) == ABOR_TSTR)
    && tlv_copy_sequence(abd->pos, abd->len, dst, dstlen);
}

size_t
abor_get_sequence_length(const abor_decoder_t *abd) {
  size_t result = 0;
  assert(abd);
  assert(abd->pos);

  if (abd->len > 0) {
    abor_type type = abor_get_major_type(abd->pos);
    if ((type >= ABOR_BSTR) || (type <= ABOR_MAP)) {
      uint64_t num;
      result = parse_number(abd->pos, abd->len, &num);
      /* Check if num number of bytes would fit in input, otherwise
       * return 0. This gives an accurate size for BSTR and TSTR but
       * not for ARRAY and MAP. */
      if (result && (result + num <= abd->len)) {
        result = num & SIZE_MAX;
      }
    }
  }
  return result;
}

const uint8_t *
abor_get_bytes(const abor_decoder_t *abd) {
  const uint8_t *result = NULL;
  abor_type mt;
  assert(abd);

  if (abd->len == 0)
    return NULL;

  mt = abor_get_major_type(abd->pos);
  if (mt == ABOR_BSTR || mt == ABOR_TSTR) {
    uint64_t num;
    size_t parsed;
    parsed = parse_number(abd->pos, abd->len, &num);
    if (parsed) {
      result = abd->pos + parsed;
    }
  }
  return result;
}

const char *
abor_get_text(const abor_decoder_t *abd) {
  return (const char *)abor_get_bytes(abd);
}

struct abor_iterator_t {
  abor_type type;
  size_t nitems;
  const uint8_t *pos;
  size_t len;
};

abor_iterator_t *
abor_iterate_start(const abor_decoder_t *abd) {
  abor_iterator_t *it = NULL;
  uint64_t nitems;
#ifdef ABOR_STATIC_MAPGET_NUM_ITEMS
  static abor_iterator_t it_;
#endif /* ABOR_STATIC_MAPGET_NUM_ITEMS */

  assert(abd);
  assert(abd->pos);

  if (abd->len > 0) {
    abor_type type = abor_get_major_type(abd->pos);
    if ((type == ABOR_MAP) || (type == ABOR_ARRAY)) {
      size_t parsed;
#ifdef ABOR_STATIC_MAPGET_NUM_ITEMS
      it = &it_;
#else /* ABOR_STATIC_MAPGET_NUM_ITEMS */
      it = (abor_iterator_t *)abor_alloc(sizeof(abor_iterator_t));
      if (!it)
        return NULL;
#endif /* ABOR_STATIC_MAPGET_NUM_ITEMS */
      parsed = parse_number(abd->pos, abd->len, &nitems);
      if (!parsed) {
        abor_iterate_finish(it);
        return NULL;
      }
      it->type = type;
      it->nitems = nitems & SIZE_MAX;
      it->pos = abd->pos + parsed;
      it->len = abd->len - parsed;
    }
  }
  return it;
}

abor_decoder_t *
abor_iterate_get(const abor_iterator_t *it) {
  assert(it);

  if ((it->nitems > 0) && (it->len > 0)) {
    abor_decoder_t *abd = new_decoder();
    if (abd) {
      abd->data = it->pos;
      abd->pos = it->pos;
      abd->len = it->len;
      return abd;
    }
  }
  return NULL;
}

bool
abor_iterate_next(abor_iterator_t *it) {
  size_t parsed;
  assert(it);

  /* Check if there are items available while ensuring that we do not
   * run into an underflow. */
  if (it->nitems <= 1) {
    it->nitems = 0;
    return false;
  }
  it->nitems--;

  parsed = skip_item(it->pos, it->len);
  if (!parsed)
    return false;

  it->pos += parsed;
  it->len -= parsed;
  return it->len > 0;
}

void
abor_iterate_finish(const abor_iterator_t *it) {
#ifdef ABOR_STATIC_MAPGET_NUM_ITEMS
  (void)it;
#else /* ABOR_STATIC_MAPGET_NUM_ITEMS */
  abor_free(it);
#endif /* ABOR_STATIC_MAPGET_NUM_ITEMS */
}

/************************************************************************/

const uint8_t *
abor_decode_get_raw_pointer(const abor_decoder_t *abd) {
  return abd ? abd->pos : NULL;
}

size_t
abor_decode_get_max_length(const abor_decoder_t *abd) {
  return abd ? abd->len : 0;
}

size_t
abor_decode_get_size(const abor_decoder_t *abd) {
  return (abd && abd->pos) ? skip_item(abd->pos, abd->len) : 0;
}
