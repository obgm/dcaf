/*
 * dcaf_key.h -- wrapper for DCAF-related crypto operations
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_KEY_H_
#define _DCAF_KEY_H_ 1

#include <stdbool.h>
#include <stdint.h>

struct dcaf_key_t;
typedef struct dcaf_key_t dcaf_key_t;

typedef enum {
  DCAF_NONE = 0,
  DCAF_AES_128 = 1,             /**< AES-128-CCM */
  DCAF_AES_256 = 2,             /**< AES-256-CCM */
  DCAF_HS256 = 64,              /**< HMAC-SHA256 */
  DCAF_KID = 4096               /**< key data is a kid specifier */
} dcaf_key_type;

/**
 * Creates a new DCAF key object of given @p type. This function
 * returns a pointer to a new key structure or NULL if an error
 * occurred. The key object must be released with dcaf_delete_key().
 *
 * @param type   The key type to create.
 *
 * @return A pointer to a newly allocated key object or NULL on error.
 */
dcaf_key_t *dcaf_new_key(dcaf_key_type type);

/**
 * Releases the memory that was allocated for @p key by
 * dcaf_new_key().
 *
 * @param key  A pointer to the key object to free.
 */
void dcaf_delete_key(dcaf_key_t *key);

/**
 * Sets random key data for @p key. This function returns true if @p
 * key was changed. An error occurs when no PRNG function was set
 * using dcaf_set_prng().
 *
 * @param key  The key to fill with random data.
 */
bool dcaf_key_rnd(dcaf_key_t *key);

/**
 * Sets key data. This function copies @p data_len bytes from @p data
 * into @p key. The result is true if all bytes have been stored, false
 * otherwise.
 *
 * @param key  The key to set.
 * @param data The new value for key.
 * @param data_len The number of bytes to copy from @p data into @p key.
 *                 This value may be zero to set an empty key.
 *
 * @return true on sucess, false otherwise.
 */
bool dcaf_set_key(dcaf_key_t *key, const uint8_t *data, size_t data_len);

#endif /* _DCAF_KEY_H_ */
