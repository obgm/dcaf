/*
 * dcaf_address.c -- convenience functions for CoAP address handling
 *
 * Copyright (C) 2015-2019 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2019 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifndef RIOT_VERSION
#include <netdb.h>
#endif /* RIOT_VERSION */
#include <netinet/in.h>

#include "dcaf/dcaf_address.h"
#include "dcaf/dcaf_int.h"

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef NI_MAXHOST
#define NI_MAXHOST 64
#endif /* NI_MAXHOST */

#ifdef RIOT_VERSION
#include <arpa/inet.h>
#include "net/sock/dns.h"

dcaf_result_t
dcaf_set_coap_address(const unsigned char *host, size_t host_len,
                      uint16_t port, coap_address_t *addr) {
  dcaf_result_t res = DCAF_ERROR_INTERNAL_ERROR;
  char addr_str[NI_MAXHOST + 1];
#ifdef MODULE_SOCK_DNS
  uint8_t buf[16] = {0};
  int version;

  assert(addr);
  memset(addr_str, 0, sizeof(addr_str));
  memcpy(addr_str, host, min(sizeof(addr_str) - 1, host_len));

  version = sock_dns_query(addr_str, buf, AF_UNSPEC);
  if (version > 0) {
    if (version == 4) {             /* AF_INET */
      addr->size = sizeof(struct sockaddr_in);
      memcpy(&addr->addr.sin.sin_addr, buf, sizeof(struct in_addr));
      addr->addr.sin.sin_port = htons(port);
    } else {                    /* AF_INET6 */
      addr->size = sizeof(struct sockaddr_in6);
      memcpy(&addr->addr.sin6.sin6_addr, buf, sizeof(struct in6_addr));
      addr->addr.sin6.sin6_port = htons(port);
    }
    res = DCAF_OK;
  } else {
    dcaf_log(DCAF_LOG_WARNING, "cannot resolve %s\n", addr_str);
  }
#else /* MODULE_SOCK_DNS */
  assert(addr);
  memset(addr_str, 0, sizeof(addr_str));
  memcpy(addr_str, host, min(sizeof(addr_str) - 1, host_len));

  if (inet_pton(AF_INET6, addr_str, &addr->addr.sin6.sin6_addr) == 0) {
    addr->size = sizeof(struct sockaddr_in6);
    addr->addr.sa.sa_family = AF_INET6;
    addr->addr.sin6.sin6_port = htons(port);
    res = DCAF_OK;
  } else if (inet_pton(AF_INET, addr_str, &addr->addr.sin.sin_addr) == 0) {
    addr->size = sizeof(struct sockaddr_in);
    addr->addr.sa.sa_family = AF_INET;
    addr->addr.sin.sin_port = htons(port);
    res = DCAF_OK;
  } else {
    dcaf_log(DCAF_LOG_WARNING, "%s not resolved\n", addr_str);
  }
#endif /* MODULE_SOCK_DNS */
  return res;
}

#else /* RIOT_VERSION */

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

  s = getaddrinfo(addr_str, port_str, &hints, &result);
  if (s != 0) {
    dcaf_log(DCAF_LOG_CRIT, "getaddrinfo: %s\n", gai_strerror(s));
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
#endif /* RIOT_VERSION */

uint16_t
dcaf_get_coap_port(const coap_address_t *address) {
  uint16_t network_port = 0;
  if (address) {
    switch (address->addr.sa.sa_family) {
    case AF_INET:
      network_port = address->addr.sin.sin_port;
      break;
    case AF_INET6:
      network_port = address->addr.sin6.sin6_port;
      break;
    default:
    ;
    }
  }
return ntohs(network_port);
}

void
dcaf_set_coap_port(coap_address_t *address, uint16_t port) {
  if (address) {
    switch (address->addr.sa.sa_family) {
    case AF_INET:
      address->addr.sin.sin_port = htons(port);
      break;
    case AF_INET6:
      address->addr.sin6.sin6_port = ntohs(port);
      break;
    default:
      ;
    }
  }
}
