/*
 * dcaf_debug.h -- helper functions for debugging
 *
 * Copyright (C) 2018-2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DCAF_DEBUG_H_
#define _DCAF_DEBUG_H_ 1

#include <stdint.h>

/** Pre-defined log levels akin to what is used in \b syslog. */
typedef enum {
  DCAF_LOG_EMERG=0,
  DCAF_LOG_ALERT,
  DCAF_LOG_CRIT,
  DCAF_LOG_ERR,
  DCAF_LOG_WARNING,
  DCAF_LOG_NOTICE,
  DCAF_LOG_INFO,
  DCAF_LOG_DEBUG
} dcaf_log_t;

/** Returns the current log level. */
dcaf_log_t dcaf_get_log_level(void);

/** Sets the log level to the specified value. */
void dcaf_set_log_level(dcaf_log_t level);

typedef void (*dcaf_log_handler_t) (dcaf_log_t level, const char *message);

/** Add a custom log callback, use NULL to reset default handler */
void dcaf_set_log_handler(dcaf_log_handler_t handler);

#if (defined(__GNUC__))
void dcaf_log(dcaf_log_t level,
              const char *format, ...) __attribute__ ((format(printf, 2, 3)));
#else
void dcaf_log(dcaf_log_t level, const char *format, ...);
#endif

void dcaf_debug_hexdump(const void *data, size_t len);

struct dcaf_authz_t;

void dcaf_show_ticket(dcaf_log_t level, const struct dcaf_authz_t *authz);

/**
 * Pretty-prints CBOR data by passing @len bytes of @data to
 * cbor2pretty.rb (requires the cbor2pretty.rb from cbor-diag
 * @sa https://github.com/cabo/cbor-diag)
 */
void dcaf_show_cbor(const uint8_t *data, size_t len);

#endif /* _DCAF_DEBUG_H_ */

