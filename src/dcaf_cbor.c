/*
 * dcaf_cbor.c -- CBOR compatibility wrapper libdcaf
 *
 * Copyright (C) 2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include "dcaf/dcaf_cbor.h"

#ifdef RIOT_VERSION
#include "memarray.h"
#endif /* RIOT_VERSION */

#ifdef USE_CBOR_CONTEXT
/* calloc/free functions */
static void *cbor_calloc(size_t count, size_t size, void *memblock) {
  (void)count;
  (void)size;
  (void)memblock;
  return NULL;
}
static void cbor_free(void *ptr, void *memblock) {
  (void)ptr;
  (void)memblock;
}

/* CN_CBOR block allocator context struct*/
static cn_cbor_context cbor_context =
{
    .calloc_func = cbor_calloc,
    .free_func = cbor_free,
    .context = &storage,
};
#endif  /* USE_CBOR_CONTEXT */

void
dcaf_cbor_init(void) {
}

cn_cbor *
dcaf_cbor_decode(const uint8_t *buf, size_t len, cn_cbor_errback *errp) {
#ifdef USE_CBOR_CONTEXT
  return cn_cbor_decode(buf, len, &cbor_context, errp);
#else /* USE_CBOR_CONTEXT */
  return cn_cbor_decode(buf, len, errp);
#endif /* USE_CBOR_CONTEXT */
}

void
dcaf_cbor_free(cn_cbor* cb) {
#ifdef USE_CBOR_CONTEXT
  cn_cbor_free(cb, &cbor_context);
#else /* USE_CBOR_CONTEXT */
  cn_cbor_free(cb);  
#endif /* USE_CBOR_CONTEXT */
}

cn_cbor *
dcaf_cbor_map_create(cn_cbor_errback *errp) {
#ifdef USE_CBOR_CONTEXT
  return cn_cbor_map_create(&cbor_context, errp);
#else /* USE_CBOR_CONTEXT */
  return cn_cbor_map_create(errp);
#endif /* USE_CBOR_CONTEXT */
}

cn_cbor *
dcaf_cbor_data_create(const uint8_t* data, int len,
                      cn_cbor_errback *errp) {
#ifdef USE_CBOR_CONTEXT
  return cn_cbor_data_create(data, len, &cbor_context, errp);
#else /* USE_CBOR_CONTEXT */
  return cn_cbor_data_create(data, len, errp);
#endif /* USE_CBOR_CONTEXT */
}  

cn_cbor *
dcaf_cbor_string_create(const char* data, cn_cbor_errback *errp) {
#ifdef USE_CBOR_CONTEXT
  return cn_cbor_string_create(data, &cbor_context, errp);
#else /* USE_CBOR_CONTEXT */
  return cn_cbor_string_create(data, errp);
#endif /* USE_CBOR_CONTEXT */
}

cn_cbor *
dcaf_cbor_int_create(int64_t value, cn_cbor_errback *errp) {
#ifdef USE_CBOR_CONTEXT
  return cn_cbor_int_create(value, &cbor_context, errp);
#else /* USE_CBOR_CONTEXT */
  return cn_cbor_int_create(value, errp);
#endif /* USE_CBOR_CONTEXT */
}

cn_cbor *
dcaf_cbor_float_create(float value, cn_cbor_errback *errp)  {
#ifndef CBOR_NO_FLOAT
#ifdef USE_CBOR_CONTEXT
  return cn_cbor_float_create(value, &cbor_context, errp);
#else /* USE_CBOR_CONTEXT */
  return cn_cbor_float_create(value, errp);
#endif /* USE_CBOR_CONTEXT */
#else /* CBOR_NO_FLOAT */
  return NULL;
#endif /* CBOR_NO_FLOAT */
}

cn_cbor *
dcaf_cbor_double_create(double value, cn_cbor_errback *errp) {
#ifndef CBOR_NO_FLOAT
#ifdef USE_CBOR_CONTEXT
  return cn_cbor_double_create(value, &cbor_context, errp);
#else /* USE_CBOR_CONTEXT */
  return cn_cbor_double_create(value, errp);
#endif /* USE_CBOR_CONTEXT */
#else /* CBOR_NO_FLOAT */
  return NULL;
#endif /* CBOR_NO_FLOAT */
}

bool
dcaf_cbor_mapput_int(cn_cbor* cb_map,
                     int64_t key,
                     cn_cbor *cb_value,
                     cn_cbor_errback *errp) {
#ifdef USE_CBOR_CONTEXT
  return cn_cbor_mapput_int(cb_map, key, cb_value, &cbor_context, errp);
#else /* USE_CBOR_CONTEXT */
  return cn_cbor_mapput_int(cb_map, key, cb_value, errp);
#endif /* USE_CBOR_CONTEXT */
}

bool
dcaf_cbor_mapput_string(cn_cbor* cb_map,
                        const char* key,
                        cn_cbor* cb_value,
                        cn_cbor_errback *errp) {
#ifdef USE_CBOR_CONTEXT
  return cn_cbor_mapput_string(cb_map, key, cb_value, &cbor_context, errp);
#else /* USE_CBOR_CONTEXT */
  return cn_cbor_mapput_string(cb_map, key, cb_value, errp);
#endif /* USE_CBOR_CONTEXT */
}

cn_cbor *
dcaf_cbor_array_create(cn_cbor_errback *errp) {
#ifdef USE_CBOR_CONTEXT
  return cn_cbor_array_create(&cbor_context, errp);
#else /* USE_CBOR_CONTEXT */
  return cn_cbor_array_create(errp);
#endif /* USE_CBOR_CONTEXT */
}
