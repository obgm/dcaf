/*
 * dcaf_prng.c -- random number generation
 *
 * Copyright (C) 2015-2020 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2020 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include "dcaf/dcaf_prng.h"

#ifdef ESP_PLATFORM
#include <esp_system.h>
#define PRNG_FUNC ((dcaf_rand_func_t)esp_fill_random)
#else
#define PRNG_FUNC (NULL)
#endif /* ESP_PLATFORM */

static dcaf_rand_func_t rand_func = PRNG_FUNC;

void
dcaf_set_prng(dcaf_rand_func_t rng) {
  rand_func = rng;
}

bool
dcaf_prng(uint8_t *out, size_t len) {
  if (!rand_func) {
    return false;
  }

  rand_func(out, len);
  return true;
}

