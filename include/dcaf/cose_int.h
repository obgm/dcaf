/*
 * cose_int.h -- internal COSE API (required for testing)
 *
 * Copyright (C) 2017-2020 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _COSE_INT_H_
#define _COSE_INT_H_ 1

#ifdef __cplusplus
extern "C" {
#ifdef EMACS_NEEDS_A_CLOSING_BRACKET
}
#endif
#endif

typedef struct cose_encrypt0_scratch_t {
  uint8_t iv[16];
  size_t buflen;
  uint8_t *buf;
} cose_encrypt0_scratch_t;

struct cose_bucket_t {
  const uint8_t *data;
  size_t length;
};

struct cose_obj_t {
  unsigned int type;
  unsigned int flags;
  /* The message underlying this COSE object must be valid as long
   * as the buckets are in use. */
  cose_bucket_t buckets[4];

  /** Scratch pad for intermediary structures. */
  union {
    cose_encrypt0_scratch_t encrypt0;
  } scratch;
};

static inline size_t
max_buckets(const cose_obj_t *obj) {
  return sizeof(obj->buckets)/sizeof(obj->buckets[0]);
}

#define COSE_OBJ_HAS_PROTECTED    (1 << COSE_PROTECTED)
#define COSE_OBJ_HAS_UNPROTECTED  (1 << COSE_UNPROTECTED)
#define COSE_OBJ_HAS_DATA         (1 << COSE_DATA)
#define COSE_OBJ_HAS_OTHER        (1 << COSE_OTHER)

/** Creates a new cose_obj_t. Internal use only. */
cose_obj_t *cose_obj_new(void);

#ifdef __cplusplus
}
#endif

#endif /* _COSE_INT_H_ */

