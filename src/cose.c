/*
 * cose.c -- definitions from COSE (RFC 8152)
 *
 * Copyright (C) 2017-2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <assert.h>
#include <stdio.h>  /* debug only */
#include <stdlib.h>
#include <string.h>

#include <cn-cbor/cn-cbor.h>

#include "dcaf/dcaf_int.h"
#include "dcaf/cose.h"
#include "dcaf/cose_int.h"

#define COSE_DEBUG 1

typedef enum cose_mem_type {
  COSE_MEM_OBJ,
  COSE_MEM_BUF,
} cose_mem_type;

static inline void *
cose_alloc(size_t sz) {
  return malloc(sz);
}
static inline void
cose_free(void *p) {
  free(p);
}

static void *
cose_alloc_type(cose_mem_type type) {
  switch (type) {
  case COSE_MEM_OBJ: return cose_alloc(sizeof(cose_obj_t));
  case COSE_MEM_BUF: return NULL;
  default:
    ;
  }
  return NULL;
}

static void
cose_free_type(cose_mem_type type, void *p) {
  (void)type;
  cose_free(p);
}

cose_obj_t *
cose_obj_new(void) {
  void *obj = cose_alloc_type(COSE_MEM_OBJ);

  if (obj) {
    memset(obj, 0, sizeof(cose_obj_t));
  }

  return (cose_obj_t *)obj;
}

static inline
cn_cbor *get_cbor_root(const cn_cbor *p) {
  for (; p && p->parent; p = p->parent)
    ;
  return (cn_cbor *)p;
}

void
cose_obj_delete(cose_obj_t *obj) {
  unsigned int flags;
  size_t n;

  if (!obj) {
    return;
  }

  /* Free all buckets that have the corresponding bit set in obj->flags. */
  flags = obj->flags & ((1 << max_buckets(obj)) - 1);
  for (n = 0; flags; n++, flags >>= 1) {
    if (flags & 0x01) {
      cn_cbor_free(get_cbor_root(obj->buckets[n]));
    }
  }

  switch (obj->type) {
  case COSE_ENCRYPT0: cose_free(obj->scratch.encrypt0.buf); break;
  default:
    ;
  }
  cose_free_type(COSE_MEM_OBJ, obj);
}

static inline void
log_parse_error(const cn_cbor_errback err) {
  dcaf_log(DCAF_LOG_ERR, "parse error %d at pos %d\n", err.err, err.pos);
}

const cn_cbor *
cose_get_bucket(cose_obj_t *obj, cose_bucket_type type) {
  return obj->buckets[type];
}

void
cose_set_bucket(cose_obj_t *obj, cose_bucket_type type, cn_cbor *cbor) {
  unsigned int flag = 1 << type;
  assert(obj);

  if (obj->buckets[type] && (obj->flags & flag)) {
    cn_cbor_free(get_cbor_root(obj->buckets[flag]));
  }
  obj->buckets[type] = cbor;
  obj->flags |= flag;
}

/* Helper function to simplify handling of newly created cbor
 * objects. This function returns an error code if cbor is NULL, and
 * COSE_OK otherwise.
 */
static inline cose_result_t
set_bucket(cose_obj_t *obj, cose_bucket_type type, cn_cbor *cbor) {
  if (cbor) {
    cose_set_bucket(obj, type, cbor);
    return COSE_OK;
  } else {
    return COSE_OUT_OF_MEMORY_ERROR;
  }
}

cose_result_t
cose_parse(const uint8_t *data, size_t data_len, cose_obj_t **result) {
  cose_result_t res = COSE_OK;
  cose_obj_t *obj = cose_obj_new();
  cn_cbor_errback errp;
  cn_cbor *cur;
  cn_cbor *tmp;

  if (!obj) {
    return COSE_OUT_OF_MEMORY_ERROR;
  }

  cur = cn_cbor_decode(data, data_len, &errp);

  if (!cur) {
    log_parse_error(errp);
    res = COSE_PARSE_ERROR;
    goto error;
  }

  if (cur->type == CN_CBOR_TAG) {
    /* The element is tagged, therefore, we go down own step in the
     * object hierarchy. Nested tagging is not supported. */
    obj->type = cur->v.uint;
    cur = cur->first_child;
  }

  /* Every COSE object is an array with at least three elements. */
  if ((cur->type != CN_CBOR_ARRAY) || (cur->length < 3)) {
    res = COSE_TYPE_ERROR;
    goto error;
  }

  /* The array's first element is a bstr-encoded map. We also accept
   * and empty map or nil. */
  assert(cur->first_child != NULL);
  tmp = cur->first_child;

  if ((tmp->type == CN_CBOR_NULL) ||
      (tmp->type == CN_CBOR_ARRAY && tmp->length == 0)) {
    dcaf_log(DCAF_LOG_DEBUG, "protected is empty, but encoding is wrong\n");
    tmp++;
  } else if (tmp->type == CN_CBOR_BYTES) {
    cn_cbor *p = cn_cbor_decode(tmp->v.bytes, tmp->length, &errp);
    if (!p) {
      log_parse_error(errp);
      res = COSE_PARSE_ERROR;
      goto error;
    }

    if (p->type != CN_CBOR_MAP) {
      res = COSE_TYPE_ERROR;
      cn_cbor_free(p);
      goto error;
    }

    set_bucket(obj, COSE_PROTECTED, p);
    /* TODO: p becomes invalid when data does not exist anymore. Copy? */
  } else {
    dcaf_log(DCAF_LOG_DEBUG, "encoding of protected is wrong\n");
    res = COSE_TYPE_ERROR;
    goto error;
  }

  tmp = tmp->next;
  if (tmp->type != CN_CBOR_MAP) {
    res = COSE_TYPE_ERROR;
    goto error;
  }

  obj->buckets[COSE_UNPROTECTED] = tmp;

  obj->buckets[COSE_DATA] = tmp->next;

  tmp = tmp->next;
  if (tmp) {
    /* FIXME: need to check type? */
    obj->buckets[COSE_OTHER] = tmp;
  }

  if (result) {
    /* Set flag to ensure that cose_obj_delete() releases the memory
     * for the root. After this flag is set, cur must not be free'd
     * because cose_obj_delete(obj) will call cn_cbor_free() on the
     * unprotected bucket's root node.
     */
    obj->flags |= COSE_OBJ_HAS_UNPROTECTED;

    *result = obj;
    return COSE_OK;
  }
 error:
  cn_cbor_free(get_cbor_root(cur));
  cose_obj_delete(obj);
  *result = NULL;
  return res;
}

static const cn_cbor *
from_general_headers(const cose_obj_t *obj, int cose_type) {
  const cn_cbor *cbor = NULL;

  assert(obj);

  if ((obj->buckets[COSE_PROTECTED] != NULL) &&
      (obj->buckets[COSE_PROTECTED]->type == CN_CBOR_MAP)) {
    cbor = cn_cbor_mapget_int(obj->buckets[COSE_PROTECTED], cose_type);
  }

  if (!cbor && (obj->buckets[COSE_UNPROTECTED] != NULL) &&
      (obj->buckets[COSE_UNPROTECTED]->type == CN_CBOR_MAP)) {
    cbor = cn_cbor_mapget_int(obj->buckets[COSE_UNPROTECTED], cose_type);
  }

  return cbor;
}

struct ccm_alg_map {
  cose_alg_t alg;
  uint8_t l;
  uint8_t m;
  uint8_t k;
} alg_map[] = {
  { COSE_AES_CCM_16_64_128,  2,  8, DCAF_AES_128 },
  { COSE_AES_CCM_16_64_256,  2,  8, DCAF_AES_256 },
  { COSE_AES_CCM_64_64_128,  8,  8, DCAF_AES_128 },
  { COSE_AES_CCM_64_64_256,  8,  8, DCAF_AES_256 },
  { COSE_AES_CCM_16_128_128, 2, 16, DCAF_AES_128 },
  { COSE_AES_CCM_16_128_256, 2, 16, DCAF_AES_256 },
  { COSE_AES_CCM_64_128_128, 8, 16, DCAF_AES_128 },
  { COSE_AES_CCM_64_128_256, 8, 16, DCAF_AES_256 },
  { 0, 0, 0, 0 }                /* end marker */
};

static inline ssize_t
write_type_value(unsigned int type, uint32_t value,
                 uint8_t *buf, size_t max_len) {
  ssize_t written = -1;
  type <<= 5;
  if (value < 24) {
    if (max_len >= 1) {
      buf[0] = type | value;
      written = 1;
    }
  } else if (value < 256) {
    if (max_len >= 2) {
      buf[0] = type | 24;
      buf[1] = value & 0xff;
      written = 2;
    }
  } else if (value < 65536) {
    if (max_len >= 3) {
      buf[0] = type | 25;
      buf[1] = (value >> 8) & 0xff;
      buf[2] = value & 0xff;
      written = 3;
    }
  }
  return written;
}

static inline size_t
reverse_write_type_length(unsigned int type, uint32_t length,
                          uint8_t *buf, size_t max_len) {
  size_t written = 0;

  type <<= 5;
  if (length < 24) {
    if (max_len >= 1) {
      buf[-1] = type | length;
      written = 1;
    }
  } else if (length < 256) {
    if (max_len >= 2) {
      buf[-1] = length & 0xff;
      buf[-2] = type | 24;
      written = 2;
    }
  } else if (length < 65536) {
    if (max_len >= 3) {
      buf[-1] = length & 0xff;
      buf[-2] = (length >> 8) & 0xff;
      buf[-3] = type | 25;
      written = 3;
    }
  }
  return written;
}

static inline int
nonce_len(const dcaf_crypto_param_t *params) {
  assert(params);
  return 15 - params->params.aes.l;
}

#define CBOR_MAJOR_TYPE_UINT   0
#define CBOR_MAJOR_TYPE_INT    1
#define CBOR_MAJOR_TYPE_BSTR   2
#define CBOR_MAJOR_TYPE_TSTR   3
#define CBOR_MAJOR_TYPE_ARRAY  4
#define CBOR_MAJOR_TYPE_MAP    5
#define CBOR_MAJOR_TYPE_TAG    6

cose_result_t
cose_encrypt0(cose_alg_t alg, const dcaf_key_t *key,
              const uint8_t *external_aad, size_t external_aad_len,
              const uint8_t *data, size_t *data_len,
              cose_obj_t **result) {
  cose_obj_t *obj;
  cn_cbor *tmp;
  cose_result_t res = COSE_OK;
  struct ccm_alg_map *a;
  dcaf_crypto_param_t params;
  cose_encrypt0_scratch_t *scratch = NULL;
  assert(result);

  *result = NULL;

  for (a = alg_map; (a->alg > 0) && (a->alg != alg); alg++)
    ;

  if (a->alg == 0) {
    return COSE_NOT_SUPPORTED_ERROR;
  }

  if ((obj = cose_obj_new()) == NULL) {
    res = COSE_OUT_OF_MEMORY_ERROR;
    goto finish;
  }

  obj->type = COSE_ENCRYPT0;
  res = set_bucket(obj, COSE_PROTECTED, cn_cbor_map_create(NULL));
  if (res != COSE_OK) {
    goto finish;
  }

  tmp = cn_cbor_int_create(alg, NULL);
  if (!tmp || !cn_cbor_mapput_int(obj->buckets[COSE_PROTECTED],
                                  COSE_ALG, tmp, NULL)) {
    if (tmp) cn_cbor_free(tmp);
    res = COSE_OUT_OF_MEMORY_ERROR;
    goto finish;
  }

  scratch = &obj->scratch.encrypt0;
  params.alg = a->k;
  params.params.aes.key = (dcaf_key_t *)key;
  params.params.aes.tag_len = a->m;
  params.params.aes.l = a->l;
  params.params.aes.nonce = scratch->iv;

  dcaf_prng(params.params.aes.nonce, nonce_len(&params));

  res = set_bucket(obj, COSE_UNPROTECTED, cn_cbor_map_create(NULL));
  if (res != COSE_OK) {
    goto finish;
  }

  tmp = cn_cbor_data_create(scratch->iv, nonce_len(&params), NULL);
  if (!tmp || !cn_cbor_mapput_int(obj->buckets[COSE_UNPROTECTED],
                                  COSE_IV, tmp, NULL)) {
    if (tmp) cn_cbor_free(tmp);
    res = COSE_OUT_OF_MEMORY_ERROR;
    goto finish;
  }

  /* res = set_bucket(obj, COSE_DATA, cn_cbor_data_create(data, data_len, NULL)); */
  /* if (res != COSE_OK) { */
  /*   goto finish; */
  /* } */

  uint8_t enc_structure[64] = { /* \x83\x68Encrypt0 */
    0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x30
  };
  const size_t enc_ofs = 10;
  ssize_t len = cn_cbor_encoder_write(enc_structure, enc_ofs + 1,
                              sizeof(enc_structure),
                              obj->buckets[COSE_PROTECTED]);
  if (len < 0) {
    dcaf_log(DCAF_LOG_WARNING, "Cannot encode protected in Enc_structure\n");
    res = COSE_OUT_OF_MEMORY_ERROR;
    goto finish;
  } /* else{ */
    /* cn_cbor *bstr = */
    /*   cn_cbor_data_create(enc_structure + enc_ofs, len, NULL); */
    /* if (!bstr) { */
    /*   dcaf_log(DCAF_LOG_WARNING, "Cannot create bstr from protected\n"); */
    /*   res = COSE_OUT_OF_MEMORY_ERROR; */
    /*   goto finish; */
    /* } */
    /* cn_cbor_free(bstr); */
  /* } */
  /* Serialize all buckets that are not empty. The first empty bucket
   * ends the serialization (i.e., all buckets to write must contain a
   * cbor object). */
  else if (len >= 24) {   /* need more than one byte to encode */
    /* FIXME: make sure that we have sufficient space left */
    /* make space for length specification */
    uint8_t buf[9];
    ssize_t also_written;
    also_written = write_type_value(CBOR_MAJOR_TYPE_BSTR, len,
                                    buf, sizeof(buf));
    if (also_written < 0) {
      res = COSE_SERIALIZE_ERROR;
      goto finish;
    }
    memmove(enc_structure + enc_ofs + also_written,
            enc_structure + enc_ofs + 1, len);
    memcpy(enc_structure + enc_ofs, buf, also_written);
    len += also_written;
  } else {
    enc_structure[enc_ofs] = (CBOR_MAJOR_TYPE_BSTR << 5) | len;
    len++;
  }

  if (external_aad && (external_aad_len > 0)) {
    len += cn_cbor_encoder_write(enc_structure, enc_ofs + len,
                                 sizeof(enc_structure),
                                 cn_cbor_data_create(external_aad,
                                                     external_aad_len, NULL));
  } else {
    enc_structure[enc_ofs + len++] = 0x40; /* empty bstr */
  }

  dcaf_log(DCAF_LOG_DEBUG, "cose_encrypt0: Enc_structure is:\n");
  dcaf_debug_hexdump(enc_structure, enc_ofs + len);

  dcaf_log(DCAF_LOG_DEBUG, "cose_encrypt0: plaintext to encrypt is:\n");
  dcaf_debug_hexdump(data, *data_len);

  scratch->buflen = *data_len + params.params.aes.tag_len;
  scratch->buf = cose_alloc(scratch->buflen);
  if (!scratch->buf) {
    res = COSE_OUT_OF_MEMORY_ERROR;
    goto finish;
  }

  dcaf_log(DCAF_LOG_DEBUG, "cose_encrypt0: alg: %u\n", params.alg);
  dcaf_log(DCAF_LOG_DEBUG, "cose_encrypt0: CEK is:\n");
  dcaf_debug_hexdump(params.params.aes.key->data, 16);
  dcaf_log(DCAF_LOG_DEBUG, "cose_encrypt0: IV is:\n");
  dcaf_debug_hexdump(params.params.aes.nonce, nonce_len(&params));

  dcaf_log(DCAF_LOG_DEBUG, "cose_encrypt0: M: %u, L: %u\n",
           params.params.aes.tag_len,
           params.params.aes.l);

  if (dcaf_encrypt(&params, data, *data_len,
                   (uint8_t *)enc_structure, enc_ofs + len,
                   scratch->buf, &scratch->buflen)) {
    dcaf_log(DCAF_LOG_DEBUG, "encrypt successful!\n");
    dcaf_log(DCAF_LOG_DEBUG, "result %zu bytes:\n", scratch->buflen);
    dcaf_debug_hexdump(scratch->buf, scratch->buflen);

    res = set_bucket(obj, COSE_DATA, cn_cbor_data_create(scratch->buf,
                                                         scratch->buflen,
                                                         NULL));
    if (res == COSE_OK) {
      *result = obj;
      return COSE_OK;
    }
  } else {
    res = COSE_ENCRYPT_ERROR;
  }

 finish:
  cose_obj_delete(obj);
  return res;
}

static bool
setup_crypto_params(const cose_obj_t *obj,
                    dcaf_crypto_param_t *params,
                    cose_key_callback_t cb) {
  const dcaf_key_t *k = NULL;
  const cn_cbor *cbor;

  assert(obj);
  assert(params);

  memset(params, 0, sizeof(dcaf_crypto_param_t));

  /* FIXME: check critical */

  // AES_CCM_16_64_128
  /* Lookup alg from protected or unprotected bucket */
  cbor = from_general_headers(obj, COSE_ALG);
  if (cbor) {
    if (cbor->type == CN_CBOR_INT) {
      struct ccm_alg_map *alg;
      for (alg = alg_map; alg->alg > 0; alg++) {
        if (alg->alg == cbor->v.sint) {
          params->alg = alg->k;
          params->params.aes.tag_len = alg->m;
          params->params.aes.l = alg->l;
        }
      }
    } else {
      params->alg = DCAF_AES_128;
      params->params.aes.tag_len = 8;
      params->params.aes.l = 2;
    }
  }

  /* Lookup kid parameter from protected or unprotected bucket */
  cbor = from_general_headers(obj, COSE_KID);
  if (cbor) {
    if ((cbor->type == CN_CBOR_BYTES) || (cbor->type == CN_CBOR_TEXT)) {
      k = cb(cbor->v.str, cbor->length, COSE_MODE_DECRYPT);
    } else {
      dcaf_log(DCAF_LOG_WARNING, "illegal type for kid parameter\n");
      return false;
    }
  }
  if (!(k || (k = cb(NULL, 0, COSE_MODE_DECRYPT)))) {
    dcaf_log(DCAF_LOG_ERR, "no key found\n");
    return false;
  } else {
    params->params.aes.key = (dcaf_key_t *)k;
  }

  /* Lookup iv parameter from protected or unprotected bucket */
  cbor = from_general_headers(obj, COSE_IV);
  if (cbor) {
    if ((cbor->type == CN_CBOR_BYTES) &&
        (cbor->length == nonce_len(params))) {
      params->params.aes.nonce = (uint8_t *)cbor->v.bytes;
    } else if ((cbor->type == CN_CBOR_TEXT) &&
               (cbor->length == nonce_len(params))) {
      params->params.aes.nonce = (uint8_t *)cbor->v.str;
    } else {                    /* all other types */
      return false;
    }
  }

  if (DCAF_LOG_DEBUG <= dcaf_get_log_level()) {
    dcaf_log(DCAF_LOG_DEBUG, "cose_decrypt: alg: %u\n", params->alg);
    dcaf_log(DCAF_LOG_DEBUG, "cose_decrypt: CEK is:\n");
    dcaf_debug_hexdump(params->params.aes.key->data, 16);

    dcaf_log(DCAF_LOG_DEBUG, "cose_decrypt: IV is:\n");
    dcaf_debug_hexdump(params->params.aes.nonce, nonce_len(params));

    dcaf_log(DCAF_LOG_DEBUG, "cose_decrypt: M: %u, L: %u\n",
           params->params.aes.tag_len,
           params->params.aes.l);
  }

  return true;
}

cose_result_t
cose_decrypt(cose_obj_t *obj,
             uint8_t *external_aad, size_t external_aad_len,
             uint8_t *data, size_t *data_len,
             cose_key_callback_t cb) {
  cose_type_t type;
  size_t buflen;

  assert(obj);
  assert(data);
  assert(data_len);

  buflen = *data_len;
  *data_len = 0;

  if (!obj->type) { /* guess which type we are */
    type = (obj->flags & COSE_OBJ_HAS_OTHER) ? COSE_ENCRYPT : COSE_ENCRYPT0;
  } else {
    type = obj->type;
  }

  if ((type != COSE_ENCRYPT0) && (type != COSE_ENCRYPT)) {
    dcaf_log(DCAF_LOG_ERR, "Cannot decrypt COSE object (wrong type)\n");
    return COSE_TYPE_ERROR;
  }

  if (type == COSE_ENCRYPT) {
    dcaf_log(DCAF_LOG_WARNING, "COSE_Encrypt is not yet supported\n");
    return COSE_NOT_SUPPORTED_ERROR;
  }

  /* setup Enc_structure */
  uint8_t enc_structure[1024]; /* = "\x83\x68" "Encrypt0"; */
  uint8_t *p = enc_structure + 19;
  /* This is pretty silly as we already had the serialized version.
   * And we would need to make sure that we and our peer do the c14n
   * right. */
  ssize_t len =
    cn_cbor_encoder_write(p, 0, sizeof(enc_structure),
                          obj->buckets[COSE_PROTECTED]);
  if (len < 0) {
    fprintf(stderr, "Cannot encode protected in Enc_structure\n");
    return COSE_OUT_OF_MEMORY_ERROR;
  } else{
    /* FIXME: encode bstr len and move p to the left accordingly */
    *(--p) = 0x43;
    p -= 10;
    len += 11;
    memcpy(p, "\x83\x68" "Encrypt0", 10);
  }
  if (external_aad && external_aad_len > 0) {
    len += cn_cbor_encoder_write(p, len, sizeof(enc_structure),
                                 cn_cbor_data_create(external_aad,
                                                     external_aad_len, NULL));
  } else {
    p[len++] = 0x40; /* empty bstr */
  }

  dcaf_log(DCAF_LOG_DEBUG, "cose_decrypt: Enc_structure is:\n");
  dcaf_debug_hexdump(p, len);

  dcaf_crypto_param_t params;
  if (!setup_crypto_params(obj, &params, cb)) {
    dcaf_log(DCAF_LOG_WARNING, "cose_decrypt: cannot setup crypto params\n");
    return COSE_TYPE_ERROR;
  }

  dcaf_log(DCAF_LOG_DEBUG, "cose_decrypt: plaintext to decrypt is:\n");
  dcaf_debug_hexdump(obj->buckets[COSE_DATA]->v.bytes, obj->buckets[COSE_DATA]->length);

  assert(obj->buckets[COSE_DATA] != NULL);
  if (dcaf_decrypt(&params,
                   obj->buckets[COSE_DATA]->v.bytes,
                   obj->buckets[COSE_DATA]->length,
                   p, len,
                   data, &buflen)) {
    fprintf(stdout, "decrypt successful!\n");
    fprintf(stdout, "result %zu bytes:\n", buflen);
    *data_len = buflen;
    dcaf_debug_hexdump(data, *data_len);
    return COSE_OK;
  }

  fprintf(stderr, "decrypt failed\n");
  return COSE_DECRYPT_ERROR;
}

cose_result_t
cose_serialize(const cose_obj_t *obj,
               unsigned int flags,
               uint8_t *out,
               size_t *outlen) {
  ssize_t written;
  size_t buflen, n;
  uint8_t *array_start;

  assert(obj);

  if (!obj || !out || !outlen || (*outlen == 0)) {
    return COSE_SERIALIZE_ERROR;
  }

  /* check wr and update length of output buffer and advance begin pointer */
#define CHECK_AND_UPDATE(wr)                                            \
  if ((wr) < 0) {                                                       \
    return COSE_SERIALIZE_ERROR;                                        \
  } else {                                                              \
    buflen -= (wr);                                                     \
    out += (wr);                                                        \
  }                                                                     \

  buflen = *outlen;
  if (flags & COSE_TAGGED) {
    written = write_type_value(CBOR_MAJOR_TYPE_TAG,
                               obj->type, out, buflen);
    CHECK_AND_UPDATE(written);
  }

  /* Array start placeholder and update length later (we know that we
   * have less than 24 items in our array. */
  if (buflen <= 0)
    return COSE_SERIALIZE_ERROR;

  array_start = out;
  out++;
  buflen--;

  /* Serialize all buckets that are not empty. The first empty bucket
   * ends the serialization (i.e., all buckets to write must contain a
   * cbor object). */
  written = cn_cbor_encoder_write(out, 1, buflen, obj->buckets[COSE_PROTECTED]);
  if (written < 0) {
    return COSE_SERIALIZE_ERROR;
  } else if (written >= 24) {   /* need more than one byte to encode */
    /* FIXME: make sure that we have sufficient space left */
    /* make space for length specification */
    memmove(out + written, out + 1, written);
  }
  buflen -= written;
  {
    ssize_t also_written;
    also_written = write_type_value(CBOR_MAJOR_TYPE_BSTR, written, out, buflen - 1);
    CHECK_AND_UPDATE(also_written);
    out += written;
  }

  for (n = 1; (n < max_buckets(obj)) && obj->buckets[n]; n++) {
    written = cn_cbor_encoder_write(out, 0, buflen, obj->buckets[n]);
    CHECK_AND_UPDATE(written);
  }

  /* n is the number of array items that have been output. Patch into
   * serialized value. */
  *array_start = (CBOR_MAJOR_TYPE_ARRAY << 5) | n;

  *outlen = *outlen - buflen;
  return COSE_OK;
}

#ifdef COSE_DEBUG
void cose_show_object(dcaf_log_t level, const cose_obj_t *obj) {
  assert(obj);
  (void)level;
  (void)obj;
}
#else /* COSE_DEBUG */
void
cose_show_object(dcaf_log_t level, const cose_obj_t *obj) {
  (void)level;
  (void)obj;
}
#endif /* COSE_DEBUG */
