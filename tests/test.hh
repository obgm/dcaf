/*
 * test.hh -- common declarations for DCAF unit tests
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 *
 * Extended by Sara Stadler 2018/2019
 */

#ifndef TEST_HH_
#define TEST_HH_
#include <jansson.h>
#include "dcaf/aif.h"
#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_am.h"
#include "dcaf/cose.h"
#include "dcaf/cose_int.h"
#include "dcaf/dcaf_rules.h"

dcaf_context_t *dcaf_context(void);

/* Helper structure to simplify deletion of COSE objects in smart
 * pointers. */
struct Deleter {
  void operator()(dcaf_context_t *p) { dcaf_free_context(p); }
  void operator()(str_st *p) { dcaf_delete_str(p); }
  void operator()(dcaf_nonce_t *p) { dcaf_free_type(DCAF_NONCE, p); }
  void operator()(rule_list_st *p) { dcaf_delete_rule_list(p); }
  //freed when the rule list is freed
  void operator()(attribute_conditions_st *p) { (void)p; }
  void operator()(attribute_rule_list_st *p) { dcaf_delete_attribute_rule_list(p); }
  void operator()(attribute_list_st *p) { dcaf_delete_attribute_list(p); }
  //freed when the attribute rule list is freed
  void operator()(attribute_permission_list_st *p) {(void)p; }
  void operator()(credential_list_st *p) { dcaf_delete_credential_list(p); }
  void operator()(credential_store_st *p) { dcaf_delete_credential_store(p); }
  void operator()(credential_st *p) {free(p->issuer);free(p);}
  void operator()(dcaf_aif_t *p) { dcaf_delete_aif(p); }
  void operator()(dcaf_key_t *p) { dcaf_delete_key(p); }
  void operator()(dcaf_ticket_t *p) { dcaf_free_ticket(p); }
  void operator()(dcaf_ticket_request_t *p) { dcaf_delete_ticket_request(p); }
  void operator()(dcaf_attribute_request_t *p) { dcaf_delete_attribute_request(p); }
  void operator()(cose_obj_t *p) { cose_obj_delete(p); }

  /* objects from external libraries used for testing */
  void operator()(cn_cbor *p) { cn_cbor_free(p); }
  void operator()(json_t *p) { json_decref(p); }
  void operator()(coap_pdu_t *p) { coap_delete_pdu(p); }
};

void test_log_off(void);
void test_log_on(void);

#endif /* TEST_COSE_HH_ */
