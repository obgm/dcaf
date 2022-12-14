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

struct dcaf_keystore_t;
typedef struct dcaf_keystore_t dcaf_keystore_t;

struct coap_address_t;

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

/**
 * Sets the key identifier (kid) for the given @p key. This function
 * copies @p kid_len bytes from @p kid into @p key. The result is true
 * if all bytes have been stored, false otherwise.
 *
 * @param key     The key to modify.
 * @param kid     The identifier to associate with @p key.
 * @param kid_len The number of bytes to copy from @p kid into @p key.
 *                This value may be zero to set an empty kid.
 *
 * @return true on sucess, false otherwise.
 */
bool dcaf_set_kid(dcaf_key_t *key, const uint8_t *kid, size_t kid_len);

struct dcaf_context_t;
/**
 * Adds the specified @p key to the key storage of
 * @p dcaf_context.
 *
 * @param dcaf_context The DCAF context to store the
 *                     @p key.
 * @param peer         The address of the entity with
 *                     which @p key is associated.
 * @param key          The key object to store.
 */
void dcaf_add_key(struct dcaf_context_t *dcaf_context,
                  const struct coap_address_t *peer,
                  dcaf_key_t *key);

/**
 * Retrieves a key object that has been stored for
 * the given @p peer in @p dcaf_context. This function
 * returns the associated dcaf_key_t object if found
 * or NULL if no key was associated with peer.
 *
 * @param dcaf_context   The DCAF context where to search
 *                       for the key.
 * @param peer           The address of the peer for
 *                       which to lookup the key.
 * @param kid            The key identifier as defined
 *                       for this key by @p peer. If
 *                       set to NULL, any key identifier
 *                       will match during search.
 * @param kid_length     The actual length of @p kid.
 *                       Must be set to 0 if kid is NULL.
 * @return The key stored for @p peer or NULL if no key
 *         was found.
 */
dcaf_key_t *dcaf_find_key(struct dcaf_context_t *dcaf_context,
                          const struct coap_address_t *peer,
                          const uint8_t *kid,
                          size_t kid_length);

#endif /* _DCAF_KEY_H_ */
