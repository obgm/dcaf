/*
 * dcaf_coap.c -- DCAF CoAP function wrapper
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *               2018 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <assert.h>
#include <stdint.h>

#include <timex.h>

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_coap.h"

#ifdef RIOT_VERSION

void
coap_ticks(coap_tick_t *t) {
  timex_t tx;
  assert(t);
  *t = timex_uint64(tx);
}  

#else /* !RIOT_VERSION */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void dummy(void) {
}

#endif /* RIOT_VERSION */
