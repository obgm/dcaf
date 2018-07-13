/*
 * dcaf_address.h -- convenience functions for CoAP address handling
 *
 * Copyright (C) 2015-2017 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2017 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_ADDRESS_H_
#define _DCAF_ADDRESS_H_ 1

#include "dcaf/dcaf.h"

/**
 * Sets the given CoAP address @p result to @p host and @p port,
 * respectively. This function is a convenience function that may
 * result in a (blocking) DNS operation. If @p host is NULL, only
 * the port number in @p result will be updated.
 *
 * @param host The host name to fill into @p result. 
 * @param host_len The actual length of @p host.
 * @param port  The port number in host byte order.
 * @param result The coap_address_t object to fill.
 * @return DCAF_OK on success, a DCAF error code otherwise.
 */
dcaf_result_t dcaf_set_coap_address(const unsigned char *host,
                                    size_t host_length,
                                    uint16_t port,
                                    coap_address_t *result);

#endif /* _DCAF_ADDRESS_H_ */
