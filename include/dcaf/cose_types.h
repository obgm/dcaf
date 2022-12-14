/*
 * cose_types.h -- definitions from COSE (RFC 8152)
 *
 * Copyright (C) 2017-2022 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _COSE_TYPES_H_
#define _COSE_TYPES_H_ 1

/* Common header parameters (see RFC 8152, Section 3.1) */
typedef enum {
  COSE_ALG               = 1,
  COSE_CRIT              = 2,
  COSE_CONTENT_TYPE      = 3,
  COSE_KID               = 4,
  COSE_IV                = 5,
  COSE_PARTIAL_IV        = 6,
  COSE_COUNTER_SIGNATURE = 7,
} cose_header_param;

/** COSE key map labels */
typedef enum {
  COSE_KEY_KTY           = 1,
  COSE_KEY_KID           = 2,
  COSE_KEY_ALG           = 3,
  COSE_KEY_OPS           = 4,
  COSE_KEY_BASE_IV       = 5,
} cose_key_map_label;

/** COSE key type values */
typedef enum {
  COSE_KEY_KTY_OKP       = 1,
  COSE_KEY_KTY_EC2       = 2,
  COSE_KEY_KTY_SYMMETRIC = 4,
} cose_key_type_value;

/* see RFC 8747 */
#define CWT_COSE_KEY              1
#define CWT_ENCRYPTED_COSE_KEY    2
#define CWT_KID                   3

#define COSE_KEY_K    -1

#define COSE_ALG_HS256  3

/**
 * Tag values for the major COSE object types defined in RFC 8152,
 * Section 2. These values can also be used in the CoAP Content-Format
 * option as defined in Section 16.10 of RFC 8152.
 */
typedef enum cose_type_t {
  COSE_ENCRYPT0=16,
  COSE_MAC0=17,
  COSE_SIGN1=18,
  COSE_SIGN=98,
  COSE_ENCRYPT=96,
  COSE_MAC=97,
  COSE_KEY=101,
  COSE_KEY_SET=102,
} cose_type_t;

/** COSE crypto algorithms. */
typedef enum cose_alg_t {
  /* AES key wrap algorithms (RFC 8152, Section 12.2.1): */
  COSE_A128KW=-3,
  COSE_A192W=-4,
  COSE_A256W=-5,

  /* From RFC 8152, Section 10.2: */
  COSE_AES_CCM_16_64_128=10,
  COSE_AES_CCM_16_64_256=11,
  COSE_AES_CCM_64_64_128=12,
  COSE_AES_CCM_64_64_256=13,
  COSE_AES_CCM_16_128_128=30,
  COSE_AES_CCM_16_128_256=31,
  COSE_AES_CCM_64_128_128=32,
  COSE_AES_CCM_64_128_256=33
} cose_alg_t;

#endif /* _COSE_TYPES_H_ */

