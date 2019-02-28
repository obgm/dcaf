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
#include <random>
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

/* Generate none deterministic "random" values.*/
static void
rnd(uint8_t *out, size_t len) {
  static std::random_device rd;
  static std::seed_seq seed{rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()};
  static std::mt19937 generate(seed);
  using rand_t = uint16_t;
  static std::uniform_int_distribution<rand_t> rand;

  for (; len; len -= sizeof(rand_t), out += sizeof(rand_t)) {
    rand_t v = rand(generate);
    memcpy(out, &v, std::min(len, sizeof(rand_t)));
  }
}

void test_log_off(void) {
  dcaf_set_log_level(DCAF_LOG_CRIT);
}

void test_log_on(void) {
  dcaf_set_log_level(DCAF_LOG_INFO);
}

int main(int argc, char* argv[]) {
  test_log_on();
  dcaf_set_prng(rnd);
  int result = Catch::Session().run( argc, argv );

  return result;
}
