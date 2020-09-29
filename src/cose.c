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

#include "dcaf_config.h"
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

void
cose_obj_delete(cose_obj_t *obj) {
  if (!obj) {
    return;
  }

  switch (obj->type) {
  case COSE_ENCRYPT0: cose_free(obj->scratch.encrypt0.buf); break;
  default:
    ;
  }
  cose_free_type(COSE_MEM_OBJ, obj);
}

const cose_bucket_t *
cose_get_bucket(cose_obj_t *obj, cose_bucket_type type) {
  return (obj && (type < max_buckets(obj))) ? &obj->buckets[type] : NULL;
}

static void
cose_set_bucket_data(cose_obj_t *obj, cose_bucket_type type,
                     const uint8_t *data, size_t length) {
  unsigned int flag = 1 << type;
  assert(obj);
  assert(type < (sizeof(obj->buckets) / sizeof(obj->buckets[0])));

  obj->buckets[type].data = data;
  obj->buckets[type].length = length;

  if (data && (length > 0))
    obj->flags |= flag;
  else                          /* clear flag if bucket is cleared */
    obj->flags &= ~flag;
}
  
void
cose_set_bucket(cose_obj_t *obj, cose_bucket_type type, abor_decoder_t *cbor) {
  if (cbor)
    cose_set_bucket_data(obj, type,
                         abor_decode_get_raw_pointer(cbor),
                         abor_decode_get_size(cbor));
  else  /* clear bucket */
    cose_set_bucket_data(obj, type, NULL, 0);
}

cose_result_t
cose_parse(const uint8_t *data, size_t data_len, cose_obj_t **result) {
  cose_result_t res = COSE_OK;
  cose_obj_t *obj = cose_obj_new();
  abor_decoder_t *cbor;
  abor_iterator_t *it = NULL;
  abor_type type;
  abor_decoder_t *tmp = NULL;

  if (!obj) {
    return COSE_OUT_OF_MEMORY_ERROR;
  }

  cbor = abor_decode_start(data, data_len);

  if (!cbor) {
    dcaf_log(DCAF_LOG_ERR, "cannot create CBOR decoder for COSE\n");
    res = COSE_OUT_OF_MEMORY_ERROR;;
    goto error;
  }

  /* Consume tag if present. The only supported type so far is Encrypt0. */
  obj->type = COSE_TAG_ENCRYPT0;
  abor_consume_tag(cbor, obj->type);

  /* Every COSE object is an array with at least three elements. */
  if (!abor_check_type(cbor, ABOR_ARRAY)
      || abor_get_sequence_length(cbor) < 3) {
    dcaf_log(DCAF_LOG_DEBUG, "** cose_parse: no array or too short (%zu)\n", abor_get_sequence_length(cbor));
    res = COSE_TYPE_ERROR;
    goto error;
  }

  /* The array's first element is a bstr-encoded map. We also accept
   * and empty map or nil. */
  it = abor_iterate_start(cbor);
  if (!it) {
    dcaf_log(DCAF_LOG_DEBUG, "cannot create array iterator\n");
    goto error;
  }
  tmp = abor_iterate_get(it);
  if (!tmp) {
    dcaf_log(DCAF_LOG_DEBUG, "out of memory\n");
    goto error;
  }
  type = abor_get_type(tmp);
  
  if (abor_is_null(tmp) || ((type == ABOR_ARRAY) &&
                            (abor_get_sequence_length(tmp) == 0))) {
    dcaf_log(DCAF_LOG_DEBUG, "protected is empty, but encoding is wrong\n");
    abor_decode_finish(tmp);
    abor_iterate_next(it);      /* might return false */
    tmp = abor_iterate_get(it); /* might return NULL */
  } else if (type == ABOR_BSTR) {
    size_t protected_length;
    const uint8_t *protected_data;

    protected_length = abor_get_sequence_length(tmp);
    protected_data = abor_get_bytes(tmp);

    if (!protected_data) {
      res = COSE_PARSE_ERROR;
      goto error;
    }

    /* Here, we can release the existing decoder as information is
     * stored in the array iterator. */
    abor_decode_finish(cbor);
    cbor = abor_decode_start(protected_data, protected_length);

    if (!cbor) {
      res = COSE_PARSE_ERROR;
      goto error;
    }

    if (!abor_check_type(cbor, ABOR_MAP)) {
      dcaf_log(DCAF_LOG_DEBUG, "** cose_parse: not a map 1\n");
      res = COSE_TYPE_ERROR;
      goto error;
    }

    cose_set_bucket(obj, COSE_PROTECTED, cbor);    
  } else {
    dcaf_log(DCAF_LOG_DEBUG, "encoding of protected is wrong\n");
    res = COSE_TYPE_ERROR;
    goto error;
  }

  abor_decode_finish(tmp);
  abor_iterate_next(it);      /* might return false */
  tmp = abor_iterate_get(it); /* might return NULL */
  if (!abor_check_type(tmp, ABOR_MAP)) {
      dcaf_log(DCAF_LOG_DEBUG, "** cose_parse: not a map 2\n");
    res = COSE_TYPE_ERROR;
    goto error;
  }

  cose_set_bucket(obj, COSE_UNPROTECTED, tmp);    
  if (abor_iterate_next(it)) {
    abor_decode_finish(tmp);
    tmp = abor_iterate_get(it);
    cose_set_bucket(obj, COSE_DATA, tmp);
  }

  if (abor_iterate_next(it)) {
    abor_decode_finish(tmp);
    tmp = abor_iterate_get(it);
    cose_set_bucket(obj, COSE_OTHER, tmp);    
  }

  if (result) {
    *result = obj;
    res = COSE_OK;
    goto finish;
  }
 error:
  cose_obj_delete(obj);
  *result = NULL;
 finish:
  abor_iterate_finish(it);
  abor_decode_finish(tmp);
  abor_decode_finish(cbor);
  return res;
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

static inline size_t
nonce_len(const dcaf_crypto_param_t *params) {
  assert(params);
  return 15 - params->params.aes.l;
}

static const char *
enc_structure_context(unsigned int type) {
  switch (type) {
  case COSE_ENCRYPT0: return "Encrypt0";
  case COSE_ENCRYPT: return "Encrypt";
  default:
    return NULL;
  }
}

#if DCAF_AM
static size_t
write_enc0_structure(const uint8_t *protected, size_t protected_length,
                    const uint8_t *external_aad, size_t external_aad_len,
                    uint8_t *result, size_t maxlen) {
  abor_encoder_t *abc;
  bool ok;
  abc = abor_encode_start(result, maxlen);

  /* Create the Enc_structure as array of three elements: */
  ok = (abc != NULL) && abor_write_array(abc, 3);

  /* 1. A text string identifying the context of the authenticated
   * data structure. */
  ok = ok && abor_write_string(abc, enc_structure_context(COSE_ENCRYPT0));

  /* 2. The protected attributes from the body structure encoded in a
   * bstr type.  If there are no protected attributes, a bstr of
   * length zero is used. */
  ok = ok && abor_write_bytes(abc, protected, protected_length);

  /* 3. The protected attributes from the application encoded in a
   * bstr type.  If this field is not supplied, it defaults to a zero-
   * length bstr. */
  ok = ok && abor_write_bytes(abc, external_aad, external_aad_len);

  return abor_encode_finish(abc);
}
#endif /* DCAF_AM */

#if DCAF_AM
cose_result_t
cose_encrypt0(cose_alg_t alg, const dcaf_key_t *key,
              const uint8_t *external_aad, size_t external_aad_len,
              const uint8_t *data, size_t *data_len,
              cose_obj_t **result) {
  cose_obj_t *obj;
  cose_result_t res = COSE_OK;
  struct ccm_alg_map *a;
  dcaf_crypto_param_t params;
  cose_encrypt0_scratch_t *scratch = NULL;
  abor_encoder_t *abc = NULL;
  abor_decoder_t *abd = NULL;
  uint8_t *protected;
  size_t protected_length = 32;
  size_t enc_structure_length;
  bool ok;
  assert(result);

  *result = NULL;

  for (a = alg_map; (a->alg > 0) && (a->alg != alg); alg++)
    ;

  if (a->alg == 0) {
    return COSE_NOT_SUPPORTED_ERROR;
  }

  if ((obj = cose_obj_new()) == NULL) {
    res = COSE_OUT_OF_MEMORY_ERROR;
    goto error;
  }

  obj->type = COSE_ENCRYPT0;

  /* Initialize parameter set for alg. */
  scratch = &obj->scratch.encrypt0;
  params.alg = a->k;
  params.params.aes.key = (dcaf_key_t *)key;
  params.params.aes.tag_len = a->m;
  params.params.aes.l = a->l;

  dcaf_prng(scratch->iv, nonce_len(&params));
  params.params.aes.nonce = scratch->iv;
  
  /* Estimate required size for the scratch buffer: */
  enc_structure_length = sizeof("Encrypt0")
    + external_aad_len
    + nonce_len(&params);
  /* Add some CBOR overhead for encoding of types and lengths. We can
   * be generous here because cose_encrypt0() is usually called on
   * less-constrained devices such as the Authorization Manager. */
  enc_structure_length += 64;

  /* The entire buffer contains the Enc_structure, data, and the MAC
   * tag. */
  scratch->buflen = enc_structure_length
    + *data_len
    + params.params.aes.tag_len;
  
  scratch->buf = cose_alloc(scratch->buflen);
  protected = scratch->buf + scratch->buflen - protected_length;
  abc = abor_encode_start(protected, protected_length);
  if (!scratch->buf || !abc) {
    res = COSE_OUT_OF_MEMORY_ERROR;
    goto error;
  }

  /* setup protected as CBOR map { COSE_ALG: alg }.
   *
   * scratch->buf points to the beginning of the Enc_structure,
   * starting with a single byte the array type and size (\x83),
   * followed by a bstr that encodes the protected map.
   * To serialize the protected data, some space at the end of
   * scratch->buf is used (scratch_tmp).
   */
  ok = abor_write_map(abc, 1);
  ok = ok && abor_write_int(abc, COSE_ALG);
  ok = ok && abor_write_int(abc, alg);

  protected_length = abor_encode_finish(abc);
  if (!ok || (protected_length == 0)) {
    /* error setting up the protected map */
    res = COSE_OUT_OF_MEMORY_ERROR;
    goto error;    
  }

  assert(scratch->buf + enc_structure_length < protected);
  enc_structure_length =
    write_enc0_structure(protected, protected_length,
                         external_aad, external_aad_len,
                         scratch->buf, enc_structure_length);

  /* Setup bucket protected. For better readability, we use a decoder
   * to retrieve the data. The protected data is taken from the
   * Encrypt0 structure at the beginning of the scratch buf. The
   * format is:
   *
   * Byte 0: 0x83 denoting an array with three elements
   * Byte 1: 0x68 A text string with eight characters ("Encrypt0")
   * Bytes 2-9: "Ecrypt0" (without terminating zero)
   * Bytes 10-: The serialized protected map
   * */
  assert(scratch->buf[0] == 0x83);
  assert((scratch->buf[1] & 0xe0) == (ABOR_TSTR << 5));

  /* Use sizeof() to calculate the length of the text string. As we
   * need to add one byte for the type+length encoding (0x68), there
   * is no need to subtract one for the terminating zero. */
  abd = abor_decode_start(&scratch->buf[1] + sizeof("Encrypt0"),
                          enc_structure_length - 1 - sizeof("Encrypt0"));
  if (!abd) {
    res = COSE_OUT_OF_MEMORY_ERROR;
    goto error;    
  }
  assert(abor_get_sequence_length(abd) == protected_length);
  cose_set_bucket_data(obj, COSE_PROTECTED,
                       abor_get_bytes(abd),
                       abor_get_sequence_length(abd));
  abor_decode_finish(abd);

  /* Setup unprotected as CBOR map { COSE_IV: scratch->iv .bstr }.
   * We can just continue after the Enc_structure. */
  abc = abor_encode_start(scratch->buf + enc_structure_length,
                          scratch->buflen - enc_structure_length);
  if (!abc) {
    res = COSE_OUT_OF_MEMORY_ERROR;
    goto error;    
  }
  ok = abor_write_map(abc, 1);
  ok = ok && abor_write_int(abc, COSE_IV);
  ok = ok && abor_write_bytes(abc, params.params.aes.nonce,
                              nonce_len(&params));

  cose_set_bucket_data(obj, COSE_UNPROTECTED,
                       scratch->buf + enc_structure_length,
                       abor_encode_finish(abc));

  if (!ok || (obj->buckets[COSE_UNPROTECTED].length == 0)) {
    res = COSE_OUT_OF_MEMORY_ERROR;
    goto error;
  }

  /* Setup encrypted data as byte string. For AEAD, the resulting
   * length will be *data_len + params.params.aes.tag_len. */
  size_t length_so_far =
    enc_structure_length + obj->buckets[COSE_UNPROTECTED].length;

  cose_set_bucket_data(obj, COSE_DATA,
                       scratch->buf + length_so_far,
                       scratch->buflen - length_so_far);

  /* Cast away the const for the data bucket that has just been set to
   * point into the scratch area. */
  abc = abor_encode_start((uint8_t *)obj->buckets[COSE_DATA].data,
                          obj->buckets[COSE_DATA].length);

  if (!abc || !abor_write_tlv(abc, ABOR_BSTR,
                              *data_len + params.params.aes.tag_len)) {
    res = COSE_OUT_OF_MEMORY_ERROR;
    goto error;
  }
  
  /* Update calculated length so we can calculate the start position
   * of the encrypted contents in the data bucket. */
  length_so_far += abor_encode_finish(abc);
  
  dcaf_log(DCAF_LOG_DEBUG, "cose_encrypt0: Enc_structure is:\n");
  dcaf_debug_hexdump(scratch->buf, enc_structure_length);

  dcaf_log(DCAF_LOG_DEBUG, "cose_encrypt0: plaintext to encrypt is:\n");
  dcaf_debug_hexdump(data, *data_len);

  dcaf_log(DCAF_LOG_DEBUG, "cose_encrypt0: alg: %u\n", params.alg);
  dcaf_log(DCAF_LOG_DEBUG, "cose_encrypt0: CEK is:\n");
  dcaf_debug_hexdump(params.params.aes.key->data, 16);
  dcaf_log(DCAF_LOG_DEBUG, "cose_encrypt0: IV is:\n");
  dcaf_debug_hexdump(params.params.aes.nonce, nonce_len(&params));

  dcaf_log(DCAF_LOG_DEBUG, "cose_encrypt0: M: %u, L: %u\n",
           params.params.aes.tag_len,
           params.params.aes.l);

  /* The result buffer for the encryption is the data bucket after the
   * BSTR type and length written above. */
  size_t result_len = scratch->buflen - length_so_far;
  if (!dcaf_encrypt(&params, data, *data_len,
                    scratch->buf, enc_structure_length,
                    scratch->buf + length_so_far,
                    &result_len)) {
    res = COSE_ENCRYPT_ERROR;
    goto error;
  }

  obj->buckets[COSE_DATA].length =
    scratch->buf + length_so_far + result_len - obj->buckets[COSE_DATA].data;

  dcaf_log(DCAF_LOG_DEBUG, "encrypt successful!\n");
  dcaf_log(DCAF_LOG_DEBUG, "result %zu bytes:\n", obj->buckets[COSE_DATA].length);
  dcaf_debug_hexdump(obj->buckets[COSE_DATA].data,
                     obj->buckets[COSE_DATA].length);

  res = COSE_OK;
  *result = obj;
  *data_len = result_len;
  return COSE_OK;

 error:
  cose_obj_delete(obj);
  return res;
}
#endif /* DCAF_AM */

static bool
setup_crypto_params(const cose_obj_t *obj,
                    dcaf_crypto_param_t *params,
                    cose_key_callback_t cb,
                    void *arg) {
  const dcaf_key_t *k = NULL;
  abor_decoder_t *alg = NULL, *kid = NULL, *iv = NULL;
  bool result = false;

  assert(obj);
  assert(params);

  memset(params, 0, sizeof(dcaf_crypto_param_t));

  /* Try to get needed elements from the protected bucket first. */
  if (obj->buckets[COSE_PROTECTED].length > 0) {
    abor_decoder_t *abd;
    abd = abor_decode_start(obj->buckets[COSE_PROTECTED].data,
                            obj->buckets[COSE_PROTECTED].length);
    if (!abd) {
      /* As it is unlikely that the next alloc for the unprotected
       * bucket will succeed, we give up here. */
      return false;
    }

    /* Look for alg, kid, and iv. */
    alg = abor_mapget_int(abd, COSE_ALG);
    kid = abor_mapget_int(abd, COSE_KID);
    iv = abor_mapget_int(abd, COSE_IV);
    abor_decode_finish(abd);
  }

  /* Now look for elements not found in the protected bucket. */
  if (obj->buckets[COSE_UNPROTECTED].length > 0) {
    abor_decoder_t *abd;
    abd = abor_decode_start(obj->buckets[COSE_UNPROTECTED].data,
                            obj->buckets[COSE_UNPROTECTED].length);
    if (abd) {
      if (!alg) 
        alg = abor_mapget_int(abd, COSE_ALG);
      if (!kid)
        kid = abor_mapget_int(abd, COSE_KID);
      if (!iv)
        iv = abor_mapget_int(abd, COSE_IV);

      abor_decode_finish(abd);
    }
  }

  /* FIXME: check critical */

  /* handle alg */
  if (abor_check_type(alg, ABOR_UINT)) {
    int num;
    if (abor_get_int(alg, &num)) {
      struct ccm_alg_map *algorithm;
      for (algorithm = alg_map; algorithm->alg > 0; algorithm++) {
        if (algorithm->alg == num) {
          params->alg = algorithm->k;
          params->params.aes.tag_len = algorithm->m;
          params->params.aes.l = algorithm->l;
        }
      }
    } else {
      dcaf_log(DCAF_LOG_ERR, "invalid alg parameter\n");
      goto error;
    }
  } else {              /* use default values if alg is not present */
    params->alg = DCAF_AES_128;
    params->params.aes.tag_len = 8;
    params->params.aes.l = 2;
  }

  /* handle kid parameter */
  if (abor_check_type(kid, ABOR_BSTR) || abor_check_type(kid, ABOR_TSTR)) {
    k = cb(abor_get_text(kid),
           abor_get_sequence_length(kid),
           COSE_MODE_DECRYPT,
           arg);
  } else if (kid) {
    dcaf_log(DCAF_LOG_WARNING, "illegal type for kid parameter\n");
  }

  if (!(k || (k = cb(NULL, 0, COSE_MODE_DECRYPT, arg)))) {
    dcaf_log(DCAF_LOG_ERR, "no key found\n");
    goto error;
  } else {
    params->params.aes.key = (dcaf_key_t *)k;
  }

  /* handle iv parameter */
  if (abor_check_type(iv, ABOR_BSTR) || abor_check_type(iv, ABOR_TSTR)) {
    /* The nonce is not copied; The caller of this function must
     * ensure that the data remains valid as long as the crypto
     * parameters are in use. */
    if (abor_get_sequence_length(iv) == nonce_len(params)) {
      params->params.aes.nonce = abor_get_bytes(iv);
    }
  }
  if (!params->params.aes.nonce) {
    dcaf_log(DCAF_LOG_ERR, "cose_decrypt: invalid nonce\n");
    goto error;
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

  result = true;
 error:
  abor_decode_finish(alg);
  abor_decode_finish(kid);
  abor_decode_finish(iv);
  return result;
}

cose_result_t
cose_decrypt(cose_obj_t *obj,
             uint8_t *external_aad, size_t external_aad_len,
             uint8_t *data, size_t *data_len,
             cose_key_callback_t cb,
             void *arg) {
  cose_type_t type;
  size_t buflen;
  cose_result_t result = COSE_DECRYPT_ERROR;

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
  uint8_t *enc_structure;
  bool ok;
  abor_encoder_t *abc;
  size_t len;
  /* estimate required scratch buffer size for Enc_structure */
  len = sizeof("Encrypt0") + 10 /* encoding of type and lengths */
    + obj->buckets[COSE_PROTECTED].length + external_aad_len;

  enc_structure = cose_alloc(len);
  if (!enc_structure) {
    dcaf_log(DCAF_LOG_ERR, "cose_decrypt: Cannot allocate Enc_struture\n");
    return COSE_OUT_OF_MEMORY_ERROR;
  }
  abc = abor_encode_start(enc_structure, len);

  /* Create the Enc_structure as array of three elements: */
  ok = (abc != NULL) && abor_write_array(abc, 3);

  /* 1. A text string identifying the context of the authenticated
   * data structure. */
  ok = ok && abor_write_string(abc, enc_structure_context(obj->type));

  /* 2. The protected attributes from the body structure encoded in a
   * bstr type.  If there are no protected attributes, a bstr of
   * length zero is used. */
  ok = ok && abor_write_bytes(abc,
                              obj->buckets[COSE_PROTECTED].data,
                              obj->buckets[COSE_PROTECTED].length);

  /* 3. The protected attributes from the application encoded in a
   * bstr type.  If this field is not supplied, it defaults to a zero-
   * length bstr. */
  ok = ok && abor_write_bytes(abc, external_aad, external_aad_len);

  len = abor_encode_finish(abc);
  if (ok) {
    dcaf_log(DCAF_LOG_DEBUG, "cose_decrypt: Enc_structure is:\n");
    dcaf_debug_hexdump(enc_structure, len);
  } else {
    dcaf_log(DCAF_LOG_DEBUG, "cose_decrypt: error creating Enc_structure\n");
    result = COSE_OUT_OF_MEMORY_ERROR;
    goto error;
  }

  dcaf_crypto_param_t params;
  if (!setup_crypto_params(obj, &params, cb, arg)) {
    dcaf_log(DCAF_LOG_WARNING, "cose_decrypt: cannot setup crypto params\n");
    result = COSE_TYPE_ERROR;
    goto error;
  }

  abor_decoder_t *abd = abor_decode_start(obj->buckets[COSE_DATA].data,
                                          obj->buckets[COSE_DATA].length);
  const uint8_t *cose_data;
  size_t cose_data_length;
  if (!abd) {
    dcaf_log(DCAF_LOG_DEBUG, "cose_decrypt: out of memory\n");
    result = COSE_OUT_OF_MEMORY_ERROR;
    goto error;
  }
  cose_data = abor_get_bytes(abd);
  cose_data_length = abor_get_sequence_length(abd);
  abor_decode_finish(abd);

  dcaf_log(DCAF_LOG_DEBUG, "cose_decrypt: plaintext to decrypt is:\n");
  dcaf_debug_hexdump(cose_data, cose_data_length);

  if (dcaf_decrypt(&params,
                   cose_data,
                   cose_data_length,
                   enc_structure, len,
                   data, &buflen)) {
    dcaf_log(DCAF_LOG_DEBUG, "cose_decrypt: successfully decrypted %zu bytes:\n", buflen);
    *data_len = buflen;
    dcaf_debug_hexdump(data, *data_len);
    result = COSE_OK;
    goto finish;
  }

 error:
  dcaf_log(DCAF_LOG_DEBUG, "cose_decrypt: decrypt failed\n");
 finish:
  cose_free(enc_structure);
  return result;
}

static inline uint8_t
count_bits(unsigned int val) {
  uint8_t result = 0;
  for (; val; val >>= 1)
    result += val & 1;
  return result;
}

#if DCAF_AM
cose_result_t
cose_serialize(const cose_obj_t *obj,
               unsigned int flags,
               uint8_t *out,
               size_t *outlen) {
  uint8_t num_buckets, bucket;
  abor_encoder_t *abc;

  assert(obj);

  if (!obj || !out || !outlen || (*outlen == 0)) {
    return COSE_SERIALIZE_ERROR;
  }

  abc = abor_encode_start(out, *outlen);
  if (!abc) {
    return COSE_OUT_OF_MEMORY_ERROR;
  }

  /* check wr and update length of output buffer and advance begin pointer */
#define CHECK(Cond) if (!(Cond)) { goto error; }

  if (flags & COSE_TAGGED) {
    CHECK(abor_write_tag(abc, obj->type));
  }

  /* Serialize all buckets that are in use as indicated by obj->flags.
   * The lower eight bits are reserved for COSE bucket flags. As we
   * always encode a protected bucket, we do not count the lowest
   * bit. */
  num_buckets = count_bits(obj->flags & 0xfe);

  CHECK(abor_write_array(abc, num_buckets + 1));

  /* Serialize contents of the protected bucket a bstr. */
  CHECK(abor_write_bytes(abc,
                         obj->buckets[COSE_PROTECTED].data,
                         obj->buckets[COSE_PROTECTED].length));

  /* Serialize contents of all remaining buckets, starting at bucket 1. */
  for (bucket = 1; num_buckets && (bucket < max_buckets(obj)); bucket++) {
    if (obj->flags & (1 << bucket)) {
      CHECK(abor_copy_raw(obj->buckets[bucket].data,
                          obj->buckets[bucket].length,
                          abc));
      num_buckets--;
    }
  }

  *outlen = abor_encode_finish(abc);
  return COSE_OK;
 error:
  abor_encode_finish(abc);
  return COSE_SERIALIZE_ERROR;
}
#endif /* DCAF_AM */

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
