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
typedef coap_block1_t coap_block_t;
typedef uint32_t coap_tid_t;
typedef void *coap_uri_t;
#else  /* include libcoap headers */
#include <coap/coap.h>
#endif /* RIOT_VERSION */

#endif /* _DCAF_COAP_H_ */
