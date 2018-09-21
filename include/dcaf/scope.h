/*
 * scope.h -- customizable scope check functions
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *               2018 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _SCOPE_H_
#define _SCOPE_H_ 1

#include <stdint.h>

#include "dcaf/dcaf.h"

/**
 * Scope type specifiers. Currently, only DCAF_SCOPE_AIF is defined.
 */
typedef enum {
              DCAF_SCOPE_AIF = 1,
} dcaf_scope_t;

/**
 * Callback function type for scope handler. This function
 * is called with the ticket's scope information as second
 * argument and the PDU to check against. The function 
 * must return true if and only if the scope allows the
 * requested operation in the PDU. The first argument denotes
 * the second argument's type. For DCAF_SCOPE_AIF, the
 * second argument can be cast safely to dcaf_aif_t *.
 */
typedef bool (*dcaf_check_scope_callback_t)(dcaf_scope_t,
                                            void *,
                                            const coap_pdu_t *);
#endif /* _SCOPE_H_ */

