/*
 * state.h -- dcaf transaction state
 *
 * Copyright (C) 2015-2020 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2020 Stefanie Gerdes <gerdes@tzi.org>
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
} dcaf_transaction_state_t;

typedef enum {
  DCAF_TRANSACTION_USER,
  DCAF_TRANSACTION_SYSTEM,
  DCAF_TRANSACTION_AUTO
} dcaf_transaction_type_t;

/** Definition of transaction state. */
typedef struct {
  dcaf_transaction_state_t act;
  dcaf_transaction_type_t type;

  /**
   * Counts errors related to this transaction. If too many errors
   * have occurred, the transaction fails.
   */
  unsigned short err_cnt;

  /** The future transaction depends on this transaction's state. */
  dcaf_transaction_t *future;
} dcaf_state_t;

#endif /* _DCAF_STATE_H_ */
