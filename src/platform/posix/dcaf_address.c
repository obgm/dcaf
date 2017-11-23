/*
 * dcaf_address.c -- convenience functions for CoAP address handling
 *
 * Copyright (C) 2015-2017 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2017 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "dcaf/dcaf_address.h"
#include "dcaf/dcaf_int.h"

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

dcaf_result_t
dcaf_set_coap_address(const unsigned char *host, size_t host_len,
                      uint16_t port, coap_address_t *addr) {
  dcaf_result_t res = DCAF_ERROR_INTERNAL_ERROR;
  int s;
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  char addr_str[NI_MAXHOST + 1];
  char port_str[6];

  assert(addr);
  memset(addr_str, 0, sizeof(addr_str));
  memcpy(addr_str, host, min(NI_MAXHOST, host_len));  
  snprintf(port_str, sizeof(port_str), "%u", port);

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

  s = getaddrinfo(addr_str, port_str, &hints, &result);
  if (s != 0) {
    dcaf_log(LOG_CRIT, "getaddrinfo: %s\n", gai_strerror(s));
    return DCAF_ERROR_INTERNAL_ERROR;
  }

  coap_address_init(addr);

  /* iterate through results until success */
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    if (rp->ai_addrlen <= sizeof(addr->addr)) {
      addr->size = rp->ai_addrlen;
      memcpy(&addr->addr, rp->ai_addr, rp->ai_addrlen);
      res = DCAF_OK;
      break;
    }
  }

  freeaddrinfo(result);
  return res;
}


