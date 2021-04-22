/* dcaf-client -- test client for the DCAF protocol
 *
 * This code has been adapted from libcoap/examples/client.c
 *
 * Copyright (C) 2018-2020 Olaf Bergmann <bergmann@tzi.org>
 *               2018-2020 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#endif

#include "dcaf/dcaf.h"

#undef VERSION
#define VERSION "1.0"

#define MAX_USER 128 /* Maximum length of a user name (i.e., PSK
                      * identity) in bytes. */
#define MAX_KEY   64 /* Maximum length of a key (i.e., PSK) in bytes. */

#define MAX_URI_SIZE 255
#define AM_DEFAULT_HOST "cam.libcoap.net"
#define AM_DEFAULT_PORT "7744"
#define AM_DEFAULT_PATH "/"

#define SNC_SIZE 8              /* default nonce size */

const char am_default_uri[] =
  "coaps://" AM_DEFAULT_HOST ":" AM_DEFAULT_PORT AM_DEFAULT_PATH;

dcaf_config_t config = {
                        .host = "::",
                        .coap_port = 0,
                        .coaps_port = 0,
                        .am_uri = am_default_uri
};

/* The log level (may be changed with option '-v' on the command line. */
struct {
  coap_log_t dtls;
  coap_log_t coap;
  dcaf_log_t dcaf;
} log_level = {
               .dtls = LOG_ERR,
               .coap = LOG_WARNING,
               .dcaf = DCAF_LOG_WARNING
};

int flags = 0;

static unsigned char _token_data[8];
coap_binary_t the_token = { 0, _token_data };

#define FLAGS_BLOCK 0x01

static coap_optlist_t *optlist = NULL;
/* Request URI.
 * TODO: associate the resources with transaction id and make it expireable */
const char *uri = NULL;

static coap_string_t payload = { 0, NULL };       /* optional payload to send */

unsigned char msgtype = COAP_MESSAGE_CON; /* usually, requests are sent confirmable */

typedef unsigned char method_t;
method_t method = 1;                    /* the method we are using in our requests */

coap_block_t block = { .num = 0, .m = 0, .szx = 6 };

unsigned int wait_seconds = 90;		/* default timeout in seconds */
unsigned int wait_ms = 0;
int wait_ms_reset = 0;
int obs_started = 0;
unsigned int obs_seconds = 30;          /* default observe time */
unsigned int obs_ms = 0;                /* timeout for current subscription */
int obs_ms_reset = 0;

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

static inline int
check_token(const coap_pdu_t *received) {
  coap_bin_const_t token;
  token = coap_pdu_get_token(received);
  return token.length == the_token.length &&
    memcmp(token.s, the_token.s, the_token.length) == 0;
}

static void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- DCAF example client\n"
     "Copyright (C) 2018-2020 Olaf Bergmann <bergmann@tzi.org>\n"
     "              2018-2020 Stefanie Gerdes <gerdes@tzi.org>\n\n"
     "Usage: %s [-A address] [-a URI] [-k key] [-p port] \n"
     "\t\t [-u user] [-v dcaf[,coap[,dtls]]] [method] URI\n\n"
     "\tURI can be an absolute URI or a URI prefixed with scheme and host.\n\n"
     "\tMethod can be any of GET|PUT|POST|DELETE|FETCH|PATCH|IPATCH. If no\n"
     "\tmethod was specified the default is GET.\n\n"
     "\t-A address\tinterface address to bind to\n"
     "\t-a URI\t\tauthorization manager (AM) URI (the \"token endpoint\")\n"
     "\t-k key \t\tPre-shared key for the specified user. This argument\n"
     "\t       \t\trequires (D)TLS with PSK to be available\n"
     "\t-p port\t\tListen on specified port\n"
     "\t-u user\t\tUser identity for pre-shared key mode. This argument\n"
     "\t       \t\trequires (D)TLS with PSK to be available\n"
     "\t-v num[,num[,num]] \tVerbosity level.\n"
     "\t       \t\tThe first number denotes the DCAF log level, the\n"
     "\t       \t\tsecond number the CoAP log level, and the third\n"
     "\t       \t\tnumber is the DTLS log level. Default is %d,%d,%d.\n"
     "\t-a CAM\t\tURI of the client authorization manager\n"
     "\n"
           ,program, version, program,
           log_level.dcaf, log_level.coap, log_level.dtls);
}

typedef struct {
  unsigned char code;
  const char *media_type;
} content_type_t;

/**
 * Calculates decimal value from hexadecimal ASCII character given in
 * @p c. The caller must ensure that @p c actually represents a valid
 * heaxdecimal character, e.g. with isxdigit(3).
 *
 * @hideinitializer
 */
#define hexchar_to_dec(c) ((c) & 0x40 ? ((c) & 0x0F) + 9 : ((c) & 0x0F))

static method_t
cmdline_method(char *arg) {
  static const char *methods[] =
    { "get", "post", "put", "delete", "fetch", "patch", "ipatch" };
  size_t i;

  for (i = 1; i < sizeof(methods)/sizeof(methods[0]); i++) {
    if (strcasecmp(arg,methods[i]) == 0)
      return i + 1;
  }
  return 0; /* 0 means "not found" */
}

static ssize_t
cmdline_read_user(char *arg, unsigned char *buf, size_t maxlen) {
  size_t len = strnlen(arg, maxlen);
  if (len) {
    memcpy(buf, arg, len);
  }
  return len;
}

static ssize_t
cmdline_read_key(char *arg, unsigned char *buf, size_t maxlen) {
  size_t len = strnlen(arg, maxlen);
  if (len) {
    memcpy(buf, arg, len);
    return len;
  }
  return -1;
}

static void
rnd(uint8_t *out, size_t len) {
#ifdef HAVE_GETRANDOM
  if (getrandom(out, len, 0) < 0) {
    dcaf_log(LOG_WARN, "getrandom failed: %s", strerror(errno));
  }
#else /* HAVE_GETRANDOM */
  /* FIXME: need to set a useful seed with srandom() */
  typedef long int rand_t;

  for (; len; len -= sizeof(rand_t), out += sizeof(rand_t)) {
    rand_t v = random();
    memcpy(out, &v, min(len, sizeof(rand_t)));
    if (len <= sizeof(rand_t))
      break;
  }
#endif /* HAVE_GETRANDOM */
}

static void
response_handler(struct dcaf_context_t *dcaf_context,
                 dcaf_transaction_t *transaction,
                 const coap_pdu_t *received) {
  (void)dcaf_context;
  (void)transaction;
  dcaf_log(DCAF_LOG_INFO, "got response: \n");
  coap_show_pdu(LOG_INFO, received);
}

int
main(int argc, char **argv) {
  dcaf_context_t *dcaf = NULL;
  coap_context_t *ctx;
  coap_session_t *session = NULL;
  int result = -1;
  char node_str[NI_MAXHOST] = "";
  int opt;
  unsigned char user[MAX_USER + 1], key[MAX_KEY];
  ssize_t user_length = 0, key_length = 0;

  while ((opt = getopt(argc, argv, "a:k:p:u:v:A:")) != -1) {
    switch (opt) {
    case 'A':
      strncpy(node_str, optarg, NI_MAXHOST - 1);
      node_str[NI_MAXHOST - 1] = '\0';
      break;
    case 'k':
      key_length = cmdline_read_key(optarg, key, MAX_KEY);
      break;
    case 'p':
      config.coap_port = atoi(optarg);
      config.coaps_port = config.coap_port + 1;
      break;
    case 'a':
      config.am_uri = optarg;
      break;
    case 'u':
      user_length = cmdline_read_user(optarg, user, MAX_USER);
      if (user_length >= 0)
        user[user_length] = 0;
      break;
    case 'v': {
      char *endptr;
      log_level.dcaf = strtol(optarg, &endptr, 10);
      if (*endptr == ',') {     /* read CoAP log level */
        log_level.coap = strtol(endptr + 1, &endptr, 10);
        if (*endptr == ',') {   /* read DTLS log level */
          log_level.dtls = strtol(endptr + 1, &endptr, 10);
        }
      }
      break;
    }
    default:
      usage(argv[0], VERSION);
      exit(EXIT_FAILURE);
    }
  }

  coap_startup();
  dcaf_set_log_level(log_level.dcaf);
  coap_set_log_level(log_level.coap);
  coap_dtls_set_log_level(log_level.dtls);

  if ((optind < argc) && ((method = cmdline_method(argv[optind])) > 0)) {
    optind++;
  } else {
    method = COAP_REQUEST_GET; /* default method is GET */
  }

  if (optind < argc) {
    uri = argv[optind];
  } else {
    usage(argv[0], VERSION);
    exit(EXIT_FAILURE);
  }

  if ((user_length < 0) || (key_length < 0)) {
    dcaf_log(DCAF_LOG_CRIT, "Invalid user name or key specified\n");
    goto finish;
  }
  
  /* set random number generator function for DCAF library */
  dcaf_set_prng(rnd);

  dcaf = dcaf_new_context(&config);

  if (!dcaf || !(ctx = dcaf_get_coap_context(dcaf)))
    return 2;

  if (key_length > 0) {
    dcaf_key_t *k = dcaf_new_key(DCAF_AES_128);
    if (!k) {
      dcaf_log(DCAF_LOG_CRIT, "cannot set AM key\n");
      goto finish;
    }
    dcaf_set_key(k, key, key_length);
    if (user_length > 0) {
      dcaf_set_kid(k, user, user_length);
    }
    dcaf_add_key(dcaf, dcaf_get_am_address(dcaf), k);
  }

  if (wait_seconds > 0) {
    dcaf_option_t timeout = { .v.uint = wait_seconds * 1000 };
    dcaf_set_option(dcaf, DCAF_OPTION_TIMEOUT, &timeout);
    dcaf_log(DCAF_LOG_DEBUG, "timeout is set to %u seconds\n", wait_seconds);
  }
  if (!dcaf_send_request(dcaf, method, uri, strlen(uri),
                         optlist, payload.s, payload.length,
                         response_handler,
                         DCAF_TRANSACTION_BLOCK)) {
    dcaf_log(DCAF_LOG_EMERG, "cannot send request\n");
    exit(EXIT_FAILURE);
  }

  /* reached only after dcaf_send_request() has returned */

  result = 0;

 finish:

  coap_delete_optlist(optlist);
  coap_session_release(session);
  dcaf_free_context(dcaf);
  coap_cleanup();

  return result;
}
