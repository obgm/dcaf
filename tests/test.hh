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

#include <cn-cbor/cn-cbor.h>

#include "dcaf/aif.h"
#include "dcaf/anybor.h"
#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_am.h"
#include "dcaf/cose.h"
#include "dcaf/cose_int.h"

#ifndef COAP_DEFAULT_VERSION
/* define COAP_DEFAULT_VERSION for backwards compatibility */
#define COAP_DEFAULT_VERSION (1U)
#endif /* COAP_DEFAULT_VERSION */
#ifndef COAP_PAYLOAD_START
/* define COAP_PAYLOAD_START for backwards compatibility */
#define COAP_PAYLOAD_START (0xFF)
#endif /* COAP_PAYLOAD_START */

/* Helper structure to simplify deletion of COSE objects in smart
 * pointers. */
struct Deleter {
  void operator()(dcaf_context_t *p) { dcaf_free_context(p); }

  void operator()(dcaf_aif_t *p) { dcaf_delete_aif(p); }
  void operator()(dcaf_key_t *p) { dcaf_delete_key(p); }
  void operator()(dcaf_ticket_t *p) { dcaf_free_ticket(p); }
  void operator()(dcaf_ticket_request_t *p) { dcaf_delete_ticket_request(p); }
  void operator()(cose_obj_t *p) { cose_obj_delete(p); }

  /* objects from external libraries used for testing */
  void operator()(cn_cbor *p) { cn_cbor_free(p); }
  void operator()(coap_pdu_t *p) { coap_delete_pdu(p); }
  void operator()(abor_encoder_t *p) { abor_encode_finish(p); }
  void operator()(abor_decoder_t *p) { abor_decode_finish(p); }
};

void test_log_off(void);
void test_log_on(void);

dcaf_context_t *dcaf_context(void);

#endif /* TEST_COSE_HH_ */
