/*
 * testdriver.cc -- DCAF unit tests
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

#include "dcaf/dcaf.h"

/* Generate deterministic "random" values. This function sets out to
 * the sequence 0, 1, 2, ... len-1.
 */
static void
rand_func(uint8_t *out, size_t len) {
  uint8_t n = 0;
  while(len--) {
    *out++ = n++;
  }
}

int main(int argc, char* argv[]) {

  dcaf_set_log_level(DCAF_LOG_DEBUG);
  dcaf_set_prng(rand_func);
  
  int result = Catch::Session().run( argc, argv );

  return result;
}
