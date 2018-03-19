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
#include "test.hh"

#include "dcaf/dcaf.h"

dcaf_context_t *
dcaf_context(void) {
  static std::unique_ptr<dcaf_context_t, Deleter> theContext;
  static dcaf_config_t config{"::", 7743, 7744,
      "coaps://[::1]:20000/"};

  if (theContext.get() == nullptr) {
    test_log_off();
    theContext.reset(dcaf_new_context(&config));
    test_log_on();
    assert(theContext.get() != nullptr);
  }

  return theContext.get();
}

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

void test_log_off(void) {
  dcaf_set_log_level(DCAF_LOG_CRIT);
}

void test_log_on(void) {
  dcaf_set_log_level(DCAF_LOG_DEBUG);
}

int main(int argc, char* argv[]) {
  test_log_on();
  dcaf_set_prng(rand_func);

  int result = Catch::Session().run( argc, argv );

  return result;
}
