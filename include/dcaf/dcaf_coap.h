/*
 * dcaf_coap.h -- CoAP compatibility wrapper libdcaf
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_COAP_H_
#define _DCAF_COAP_H_ 1

#ifdef RIOT_VERSION
#include <net/nanocoap.h>
#include <net/nanocoap_sock.h>
#include <net/ipv6/addr.h>

typedef struct {
  network_uint16_t port;
  ipv6_addr_t addr;
} coap_address_t;

typedef coap_block1_t coap_block_t;
typedef uint32_t coap_tid_t;
typedef void *coap_uri_t;
typedef void *coap_context;
typedef coap_pkt_t coap_pdu_t;

struct coap_endpoint_t;
typedef struct coap_endpoint_t coap_endpoint_t;
struct coap_session_t;
typedef struct coap_session_t coap_session_t;
#else  /* include libcoap headers */
#include <coap/coap.h>
#endif /* RIOT_VERSION */

#ifndef COAP_MEDIATYPE_APPLICATION_CBOR
#define COAP_MEDIATYPE_APPLICATION_CBOR (60)
#endif

#endif /* _DCAF_COAP_H_ */
