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

struct coap_address_t {
  network_uint16_t port;
  ipv6_addr_t addr;
};
typedef struct coap_address_t coap_address_t;

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

typedef uint64_t coap_time_t;
coap_time_t coap_ticks_to_rt(coap_tick_t t);

typedef struct coap_optlist_t coap_optlist_t;

#define COAP_REQUEST_POST COAP_METHOD_POST

int coap_get_data(coap_pdu_t *pkt,
                  size_t *len,
                  unsigned char **data);

int coap_add_data(coap_pdu_t *pkt,
                  unsigned int len,
                  const unsigned char *data);

#else  /* include libcoap headers */

#include <coap/coap.h>

#define COAP_CODE_BAD_REQUEST  (COAP_RESPONSE_CODE(400))
#define COAP_CODE_UNAUTHORIZED (COAP_RESPONSE_CODE(401))
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

/**
 * Returns the CoAP request method or response code of
 * the specified @p pdu.
 *
 * @param pdu  The CoAP pdu to retrieve the code from.
 *
 * @return The contents of the @p pdu's code field.
 */
uint8_t coap_get_method(const coap_pdu_t *pdu);

/**
 * Returns the CoAP response code of the specified @p pdu.  This
 * function is just a convenience function that calls
 * coap_get_method().
 *
 * @param pdu  The CoAP pdu to retrieve the code from.
 *
 * @return The contents of the @p pdu's code field.
 */
static inline uint8_t coap_get_response_code(const coap_pdu_t *pdu) {
  return coap_get_method(pdu);
}


/**
 * Set the CoAP response code for the specified @p pdu.
 *
 * @param pdu  The CoAP pdu to set the code.
 * @param code The CoAP code to set.
 */
static inline void coap_set_response_code(coap_pdu_t *pdu,
                                          uint8_t code) {
#ifdef RIOT_VERSION
  coap_hdr_set_code(pdu->hdr, code);
#else /* !RIOT_VERSION */
  pdu->code = code;
#endif /* RIOT_VERSION */
}

/**
 * Retrieves the resource URI from @p pdu into
 * @p buf. This function will write at most
 * @p buf_len bytes. The return value is 0 if
 * the URI did not fit into @p buf, or if an
 * internal error occurred.
 * @p *buf_len is set to the number of bytes written
 * even if the URI was clipped. In case of an error,
 * @p *buf_len will be 0 and the function's return
 * valued will be 0 as well.
 *
 * @param pdu     The CoAP pdu to retrieve the URI from.
 * @param buf     The buffer where the URI is copied.
 * @param buf_len Points to the maximum number of bytes
 *                that @p buf can hold when the function
 *                is called and will be updated to the
 *                actual number of bytes written.
 * @param flags   Must be set to 0 for now.
 *
 * @return 0 if the URI was clipped, non-zero otherwise.
 */
int coap_get_resource_uri(const coap_pdu_t *pdu,
                          uint8_t *buf, size_t *buf_len,
                          int flags);

/**
 * Returns a pointer to the token of @p pdu.
 * The pointer may be NULL for a zero-length token.
 *
 * @param pdu The CoAP PDU.
 *
 * @return A pointer to the start of the @p pdu's
 *         token, or NULL.
 */
const uint8_t *coap_get_token(const coap_pdu_t *pdu);

/**
 * Returns the size of the @p pdu's token.
 *
 * @param pdu The CoAP PDU.
 *
 * @return The size of the token in bytes.
 */
size_t coap_get_token_length(const coap_pdu_t *pdu);

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
