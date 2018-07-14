/*
 * state.h -- dcaf transaction state
 *
 * Copyright (C) 2015-2016 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2016 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_STATE_H_
#define _DCAF_STATE_H_ 1

typedef enum {
  DCAF_STATE_IDLE,
  DCAF_STATE_UNAUTHORIZED, 
  DCAF_STATE_ACCESS_REQUEST,
  DCAF_STATE_TICKET_REQUEST,
  DCAF_STATE_TICKET_GRANT,
  DCAF_STATE_AUTHORIZED
} dcaf_state_t;

#endif /* _DCAF_STATE_H_ */
