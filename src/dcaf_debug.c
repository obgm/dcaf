/*
 * dcaf_debug.c -- helper functions for debugging
 *
 * Copyright (C) 2018-2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "dcaf/dcaf_debug.h"

/* The external program used to output CBOR data in debug mode. */
#define CBOR2PRETTY "cbor2pretty.rb"

static dcaf_log_t maxlog = DCAF_LOG_WARNING; /* default maximum log level */

dcaf_log_t 
dcaf_get_log_level(void) {
  return maxlog;
}

void
dcaf_set_log_level(dcaf_log_t level) {
  maxlog = level;
}

/* this array has the same order as the type dcaf_log_t */
static char *loglevels[] = {
  "EMRG", "ALRT", "CRIT", "ERR", "WARN", "NOTE", "INFO", "DEBG" 
};

static dcaf_log_handler_t log_handler = NULL;

void dcaf_set_log_handler(dcaf_log_handler_t handler) {
  log_handler = handler;
}

void dcaf_log(dcaf_log_t level, const char *format, ...) {
  if (maxlog < level)
    return;

  if (log_handler) {
    char message[128];
    va_list ap;
    va_start(ap, format);
    vsnprintf(message, sizeof(message), format, ap);
    va_end(ap);
    log_handler(level, message);
  } else {
    /* char timebuf[32]; */
    /* coap_tick_t now; */
    va_list ap;
    FILE *log_fd;
  
    log_fd = level <= DCAF_LOG_CRIT ? stderr : stdout;

    /* FIXME: put timestamp */
    /* if (print_timestamp(timebuf,sizeof(timebuf), now)) */
    /*   fprintf(log_fd, "%s ", timebuf); */

    if (level <= DCAF_LOG_DEBUG)
      fprintf(log_fd, "%s ", loglevels[level]);

    va_start(ap, format);
    vfprintf(log_fd, format, ap);
    va_end(ap);
    fflush(log_fd);
  }
}

void
dcaf_debug_hexdump(const void *data, size_t len) {
  const uint8_t *p = (const uint8_t *)data;
  size_t n;

  if (maxlog < DCAF_LOG_DEBUG)
    return;

  for (n = 0; n < len; n++, p++) {
    fprintf(stdout, "%02x", *p);
    if ((n+1) % 8 == 0) {
      fprintf(stdout, "\n");
    } else {
      fprintf(stdout, " ");
    }
  }
  fprintf(stdout, "\n");
}

void dcaf_show_ticket(dcaf_log_t level, const struct dcaf_authz_t *authz) {
  (void)level;
  (void)authz;
}

void
dcaf_show_cbor(const uint8_t *data, size_t len) {
  /* call external program if not running as super user */
#if DCAF_PRETTY_PRINT_CBOR
  if (geteuid() != 0) {
    /* open cbor2pretty.rb as pipe and suppress error output. */
    FILE *pipe = popen(CBOR2PRETTY " 2>/dev/null", "w");
    if (pipe) {
      size_t written = fwrite((void *)data, 1, len, pipe);
      if (written < len) {
        fprintf(stdout, "error when writing to '" CBOR2PRETTY "'\n");
      }
      pclose(pipe);
    }
  }
#else /* DCAF_PRETTY_PRINT_CBOR */
  (void)data;
  (void)len;
#endif /* DCAF_PRETTY_PRINT_CBOR */
}
