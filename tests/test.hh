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

#include "dcaf/aif.h"
#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/cose.h"
#include "dcaf/cose_int.h"

dcaf_context_t *dcaf_context(void);

/* Helper structure to simplify deletion of COSE objects in smart
 * pointers. */
struct Deleter {
  void operator()(dcaf_context_t *p) { dcaf_free_context(p); }

  void operator()(dcaf_aif_t *p) { dcaf_delete_aif(p); }
  void operator()(dcaf_key_t *p) { dcaf_delete_key(p); }
  void operator()(dcaf_ticket_t *p) { dcaf_free_ticket(p); }
  void operator()(cose_obj_t *p) { cose_obj_delete(p); }

  /* objects from external libraries used for testing */
  void operator()(cn_cbor *p) { cn_cbor_free(p); }
  void operator()(coap_pdu_t *p) { coap_delete_pdu(p); }
};

void test_log_off(void);
void test_log_on(void);

#endif /* TEST_COSE_HH_ */
