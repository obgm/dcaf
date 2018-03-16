/*
 * dcaf_debug.h -- helper functions for debugging
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
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
typedef struct dcaf_authz_t dcaf_authz_t;

struct cose_obj_t;
typedef struct cose_obj_t cose_obj_t;

void dcaf_show_ticket(dcaf_log_t level, const dcaf_authz_t *authz);

#endif /* _DCAF_DEBUG_H_ */

