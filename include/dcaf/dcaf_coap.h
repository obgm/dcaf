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
typedef enum {
              COAP_PROTO_NONE=0,
              COAP_PROTO_UDP=1,
              COAP_PROTO_DTLS=2,
} coap_proto_t;

typedef uint64_t coap_tick_t;
void coap_ticks(coap_tick_t *t);
#else  /* include libcoap headers */
#include <coap/coap.h>
#endif /* RIOT_VERSION */

/**
 * Returns the Content Format specified in @p pdu
 * or -1 if none was given.
 *
 * @param pdu  The CoAP pdu to search for Content-Format.
 *
 * @return The Content-Format value from @p pdu or
 *         -1 if no Content-Format was specified.
 */
int coap_get_content_format(const coap_pdu_t *pdu);

#ifndef COAP_MEDIATYPE_TEXT_PLAIN
#define COAP_MEDIATYPE_TEXT_PLAIN (0)
#endif

#ifndef COAP_MEDIATYPE_APPLICATION_CBOR
#define COAP_MEDIATYPE_APPLICATION_CBOR (60)
#endif

#ifndef COAP_OPTION_CONTENT_FORMAT
#define COAP_OPTION_CONTENT_FORMAT (12)
#endif

#ifndef COAP_OPTION_MAXAGE
#define COAP_OPTION_MAXAGE (14)
#endif

#ifndef COAP_DEFAULT_PORT
#ifdef COAP_PORT
#define COAP_DEFAULT_PORT COAP_PORT
#else
#define COAP_DEFAULT_PORT (5683)
#endif /* COAP_PORT */
#endif /* COAP_DEFAULT_PORT */

#ifndef COAPS_DEFAULT_PORT
#define COAPS_DEFAULT_PORT ((COAP_DEFAULT_PORT) + 1)
#endif /* COAPS_DEFAULT_PORT */

#endif /* _DCAF_COAP_H_ */
