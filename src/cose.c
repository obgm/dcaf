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

#define COSE_DEBUG 1

typedef struct cose_obj_t {
  unsigned int type;
  unsigned int flags;
  const cn_cbor *buckets[4];

  /**
   * Scratch pad for intermediary structures. If not NULL, this
   * buffer holds at least COSE_SCRATCHPAD_SIZE bytes.
   */
  uint8_t *scratch;
} cose_obj_t;

bool
cose_encrypt0(const dcaf_crypto_param_t *params,
              const uint8_t *message, size_t message_len,
              const uint8_t *extaad, size_t extaad_len,
              uint8_t *result, size_t *result_len) {
  cn_cbor *cose = cn_cbor_array_create(NULL);
  (void)params;
  (void)message;
  (void)message_len;
  (void)extaad;
  (void)extaad_len;
  (void)result;
  (void)result_len;
  
  if (!cose) {
    return false;
  }

  cn_cbor_array_append(cose,
                       cn_cbor_string_create("Encrypt0", NULL),
                       NULL);

  return true;
}

/**
 * Size of internal scratch pad structure for passing around
 * intermediary data.
 */
#define COSE_SCRATCHPAD_LENGTH 64

typedef enum cose_bucket_type {
  COSE_PROTECTED,
  COSE_UNPROTECTED,
  COSE_DATA,
  COSE_OTHER,
} cose_bucket_type;

#define COSE_OBJ_HAS_PROTECTED    (1 << COSE_PROTECTED)
#define COSE_OBJ_HAS_UNPROTECTED  (1 << COSE_UNPROTECTED)
#define COSE_OBJ_HAS_DATA         (1 << COSE_DATA)
#define COSE_OBJ_HAS_OTHER        (1 << COSE_OTHER)

typedef enum cose_mem_type {
  COSE_MEM_OBJ,
  COSE_MEM_SCRATCHPAD
} cose_mem_type;

static void *
cose_alloc_type(cose_mem_type type) {
  switch (type) {
  case COSE_MEM_OBJ: return malloc(sizeof(cose_obj_t));
  case COSE_MEM_SCRATCHPAD: return malloc(COSE_SCRATCHPAD_LENGTH);
  default:
    ;
  }
  return NULL;
}   

static void
cose_free_type(cose_mem_type type, void *p) {
  (void)type;
  free(p);
}

static cose_obj_t *
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
  size_t n;
  unsigned int flags;

  if (!obj) {
    return;
  }

  /* Free all buckets that have the corresponding bit set in obj->flags. */
  flags = obj->flags & ((1 << sizeof(obj->buckets)/sizeof(*obj->buckets)) - 1);
  for (n = 0; flags; n++, flags >>= 1) {
    if (flags & 0x01) {
      cn_cbor_free(get_cbor_root(obj->buckets[n]));
    }
  }

  cose_free_type(COSE_MEM_SCRATCHPAD, obj->scratch);
  cose_free_type(COSE_MEM_OBJ, obj);
}

static inline void
log_parse_error(const cn_cbor_errback err) {
  dcaf_log(DCAF_LOG_ERR, "parse error %d at pos %d\n", err.err, err.pos);
}

cose_result_t
cose_parse(const uint8_t *data, size_t data_len, cose_obj_t **result) {
  cose_result_t res = COSE_OK;
  cose_obj_t *obj = cose_obj_new();
  cn_cbor_errback errp;
  const cn_cbor *cur;
  const cn_cbor *tmp;

  if (!obj) {
    return COSE_OUT_OF_MEMORY_ERROR;
  }

  cur = cn_cbor_decode(data, data_len, &errp);

  if (!cur) {
    log_parse_error(errp);
    return COSE_PARSE_ERROR;
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

  dcaf_log(DCAF_LOG_DEBUG, "Found array with %d elements.\n", cur->length);

  /* The array's first element is a bstr-encoded map. We also accept
   * and empty map or nil. */
  assert(cur->first_child != NULL);
  tmp = cur->first_child;

  if ((tmp->type == CN_CBOR_NULL) ||
      (tmp->type == CN_CBOR_ARRAY && tmp->length == 0)) {
    dcaf_log(LOG_DEBUG, "protected is empty, but encoding is wrong\n");
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

    obj->flags |= COSE_OBJ_HAS_PROTECTED;
    obj->buckets[COSE_PROTECTED] = p;
  } else {
    dcaf_log(LOG_DEBUG, "encoding of protected is wrong\n");
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
    if (cbor->type == CN_CBOR_BYTES) {
      params->params.aes.nonce_len = cbor->length;
      params->params.aes.nonce = (uint8_t *)cbor->v.bytes;
    } else if (cbor->type == CN_CBOR_TEXT) {
      params->params.aes.nonce_len = cbor->length;
      params->params.aes.nonce = (uint8_t *)cbor->v.str;
    } else {                    /* all other types */
      return false;
    }
  }

  if (DCAF_LOG_DEBUG <= dcaf_get_log_level()) {
    dcaf_log(DCAF_LOG_DEBUG, "CEK is:\n");
    dcaf_debug_hexdump(k->data, k->length);

    dcaf_log(DCAF_LOG_DEBUG, "IV is:\n");
    dcaf_debug_hexdump(params->params.aes.nonce, params->params.aes.nonce_len);
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
    fprintf(stderr, "Cannot decrypt COSE object (wrong type)\n");
    return COSE_TYPE_ERROR;
  }

  if (type == COSE_ENCRYPT) {
    fprintf(stderr, "COSE_Encrypt is not yet supported\n");
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

  fprintf(stdout, "Enc_structure is:\n");
  dcaf_debug_hexdump(p, len);

  dcaf_crypto_param_t params;
  if (!setup_crypto_params(obj, &params, cb)) {
    fprintf(stderr, "cannot setup crypto params\n");
    return COSE_TYPE_ERROR;
  }

  fprintf(stdout, "plaintext to decrypt is:\n");
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

#ifdef COSE_DEBUG
void cose_show_object(dcaf_log_t level, const cose_obj_t *obj) {
  assert(obj);
  (void)level;
  
}
#else /* COSE_DEBUG */
void
cose_show_object(dcaf_log_t level, const cose_obj_t *obj) {
  (void)level;
  (void)obj;
}
#endif /* COSE_DEBUG */
