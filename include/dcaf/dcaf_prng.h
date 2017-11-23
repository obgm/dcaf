/*
 * dcaf_prng.h -- random number generation
 *
 * Copyright (C) 2015-2017 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2017 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_PRNG_H_
#define _DCAF_PRNG_H_ 1

#include <stddef.h>
#include <stdint.h>

typedef void (*dcaf_rand_func_t)(uint8_t *out, size_t len);
void dcaf_set_prng(dcaf_rand_func_t rng);
int dcaf_prng(uint8_t *out, size_t len);

#endif /* _DCAF_PRNG_H_ */
