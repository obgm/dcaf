/*
 * test.hh -- common declarations for DCAF unit tests
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef TEST_HH_
#define TEST_HH_

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/cose.h"
#include "dcaf/cose_int.h"

/* Helper structure to simplify deletion of COSE objects in smart
 * pointers. */
struct Deleter {
  void operator()(dcaf_key_t *p) { dcaf_delete_key(p); }
  void operator()(dcaf_authz_t *p) { dcaf_delete_authz(p); }
  void operator()(cose_obj_t *p) { cose_obj_delete(p); }
  void operator()(cn_cbor *p) { cn_cbor_free(p); }
};

#endif /* TEST_COSE_HH_ */
