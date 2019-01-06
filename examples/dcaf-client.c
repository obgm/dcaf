/* dcaf-client -- test client for the DCAF protocol
 *
 * This code has been adapted from libcoap/examples/client.c
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *               2018 Stefanie Gerdes <gerdes@tzi.org>
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

#include <coap/coap.h>
#include <coap/coap_dtls.h>

#include "dcaf/dcaf.h"

#ifndef dcaf_log
#define dcaf_log coap_log
#endif

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
dcaf_log_t log_level = DCAF_LOG_WARNING;

int flags = 0;

static unsigned char _token_data[8];
coap_binary_t the_token = { 0, _token_data };

#define FLAGS_BLOCK 0x01

static coap_optlist_t *optlist = NULL;
/* Request URI.
 * TODO: associate the resources with transaction id and make it expireable */
const char *uri = NULL;

/* reading is done when this flag is set */
static int ready = 0;

static coap_string_t output_file = { 0, NULL };   /* output file name */
static FILE *file = NULL;               /* output file stream */

static coap_string_t payload = { 0, NULL };       /* optional payload to send */

static int reliable = 0;

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

static int
append_to_output(const uint8_t *data, size_t len) {
  size_t written;

  if (!file) {
    if (!output_file.s || (output_file.length && output_file.s[0] == '-'))
      file = stdout;
    else {
      if (!(file = fopen((char *)output_file.s, "w"))) {
        perror("fopen");
        return -1;
      }
    }
  }

  do {
    written = fwrite(data, 1, len, file);
    len -= written;
    data += written;
  } while ( written && len );
  fflush(file);

  return 0;
}

static void
close_output(void) {
  if (file) {

    /* add a newline before closing in case were writing to stdout */
    if (!output_file.s || (output_file.length && output_file.s[0] == '-'))
      fwrite("\n", 1, 1, file);

    fflush(file);
    fclose(file);
  }
}

static coap_pdu_t *
coap_new_request(coap_context_t *ctx,
                 coap_session_t *session,
                 method_t m,
                 coap_optlist_t **options,
                 unsigned char *data,
                 size_t length) {
  coap_pdu_t *pdu;
  (void)ctx;

  if (!(pdu = coap_new_pdu(session)))
    return NULL;

  pdu->type = msgtype;
  pdu->tid = coap_new_message_id(session);
  pdu->code = m;

  if ( !coap_add_token(pdu, the_token.length, the_token.s)) {
    coap_log(LOG_DEBUG, "cannot add token to request\n");
  }

  if (options)
    coap_add_optlist_pdu(pdu, options);

  if (length) {
    if ((flags & FLAGS_BLOCK) == 0)
      coap_add_data(pdu, length, data);
    else
      coap_add_block(pdu, length, data, block.num, block.szx);
  }

  return pdu;
}

static int
resolve_address(const coap_str_const_t *server, struct sockaddr *dst) {

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error, len=-1;

  memset(addrstr, 0, sizeof(addrstr));
  if (server->length)
    memcpy(addrstr, server->s, server->length);
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, NULL, &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
    switch (ainfo->ai_family) {
    case AF_INET6:
    case AF_INET:
      len = ainfo->ai_addrlen;
      memcpy(dst, ainfo->ai_addr, len);
      goto finish;
    default:
      ;
    }
  }

 finish:
  freeaddrinfo(res);
  return len;
}

#define HANDLE_BLOCK1(Pdu)                                        \
  ((method == COAP_REQUEST_PUT || method == COAP_REQUEST_POST) && \
   ((flags & FLAGS_BLOCK) == 0) &&                                \
   ((Pdu)->hdr->code == COAP_RESPONSE_CODE(201) ||                \
    (Pdu)->hdr->code == COAP_RESPONSE_CODE(204)))

static inline int
check_token(coap_pdu_t *received) {
  return received->token_length == the_token.length &&
    memcmp(received->token, the_token.s, the_token.length) == 0;
}

static void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- DCAF example client\n"
     "Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>\n"
     "              2018 Stefanie Gerdes <gerdes@tzi.org>\n\n"
     "Usage: %s [-A address] [-a URI] [-k key] [-p port] \n"
     "\t\t [-u user] [-v verbosity] [method] URI\n\n"
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
     "\t-v num \t\tVerbosity level (default: %d)\n"
     "\t-a CAM\t\tURI of the client authorization manager\n"
     "\n"
           ,program, version, program, log_level);
}

typedef struct {
  unsigned char code;
  const char *media_type;
} content_type_t;

static uint16_t
get_default_port(const coap_uri_t *u) {
  return coap_uri_scheme_is_secure(u) ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT;
}

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

static coap_session_t *
get_session(
  coap_context_t *ctx,
  const char *local_addr,
  const char *local_port,
  coap_proto_t proto,
  coap_address_t *dst,
  const char *identity,
  const uint8_t *key,
  unsigned key_len
) {
  coap_session_t *session = NULL;

  if (local_addr) {
    int s;
    struct addrinfo hints;
    struct addrinfo *result = NULL, *rp;

    memset( &hints, 0, sizeof( struct addrinfo ) );
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = COAP_PROTO_RELIABLE(proto) ? SOCK_STREAM : SOCK_DGRAM; /* Coap uses UDP */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV | AI_ALL;

    s = getaddrinfo( local_addr, local_port, &hints, &result );
    if ( s != 0 ) {
      fprintf( stderr, "getaddrinfo: %s\n", gai_strerror( s ) );
      return NULL;
    }

    /* iterate through results until success */
    for ( rp = result; rp != NULL; rp = rp->ai_next ) {
      coap_address_t bind_addr;
      if ( rp->ai_addrlen <= sizeof( bind_addr.addr ) ) {
	coap_address_init( &bind_addr );
	bind_addr.size = rp->ai_addrlen;
	memcpy( &bind_addr.addr, rp->ai_addr, rp->ai_addrlen );
        if ((identity || key) && (proto == COAP_PROTO_DTLS)) {
	  session = coap_new_client_session_psk(ctx, &bind_addr, dst, proto,
                                                 identity, key, key_len);
        } else {
	  session = coap_new_client_session(ctx, &bind_addr, dst, proto);
        }
	if (session)
	  break;
      }
    }
    freeaddrinfo(result);
  } else {
    if ((identity || key) && (proto == COAP_PROTO_DTLS))
      session = coap_new_client_session_psk(ctx, NULL, dst, proto,
                                            identity, key, key_len);
    else {
      session = coap_new_client_session(ctx, NULL, dst, proto);
    }
  }
  return session;
}

static void
prepare_message(int message_type) {
  static uint8_t buf[1024];
  cn_cbor *cbor = NULL;

  switch (message_type) {
  case 1: { /* ticket request */
    cn_cbor *scope;

    method = COAP_REQUEST_POST;

    /* set content type to application/dcaf+cbor */
    coap_insert_optlist(&optlist,
        coap_new_optlist(COAP_OPTION_CONTENT_FORMAT,
                         coap_encode_var_safe(buf, sizeof(buf),
                                              DCAF_MEDIATYPE_DCAF_CBOR),
                         buf));

    /* set payload */
    cbor = cn_cbor_map_create(NULL);
    cn_cbor_mapput_int(cbor, DCAF_TICKET_ISS,
                       cn_cbor_string_create("foo", NULL),
                       NULL);
    cn_cbor_mapput_int(cbor, DCAF_TICKET_AUD,
                       cn_cbor_string_create("bar", NULL),
                       NULL);
    scope = cn_cbor_array_create(NULL);
    cn_cbor_array_append(scope, cn_cbor_string_create("/restricted", NULL), NULL);
    cn_cbor_array_append(scope, cn_cbor_int_create(5, NULL), NULL);
    cn_cbor_mapput_int(cbor, DCAF_TICKET_SCOPE, scope, NULL);

    dcaf_prng(buf, SNC_SIZE);
    cn_cbor_mapput_int(cbor, DCAF_TICKET_SNC,
                       cn_cbor_data_create(buf, SNC_SIZE, NULL),
                       NULL);
    break;
  }
  default:
    ;
  }

  if (cbor) {
    payload.length = cn_cbor_encoder_write(buf, 0, sizeof(buf), cbor);
    if (payload.length > 0) {
      payload.s = buf;
    }
  }
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

int
main(int argc, char **argv) {
  dcaf_context_t *dcaf = NULL;
  coap_context_t *ctx;
  coap_session_t *session = NULL;
  coap_address_t dst;
  int result = -1;
  coap_pdu_t  *pdu;
  static coap_str_const_t server;
  uint16_t port = COAP_DEFAULT_PORT;
  char node_str[NI_MAXHOST] = "";
  int opt, res;
  unsigned char user[MAX_USER + 1], key[MAX_KEY];
  ssize_t user_length = 0, key_length = 0;
  int create_uri_opts = 1;
  int message_type = -1;

  while ((opt = getopt(argc, argv, "a:k:p:u:v:A:M:")) != -1) {
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
    case 'M':
      message_type = atoi(optarg);
      break;
    case 'u':
      user_length = cmdline_read_user(optarg, user, MAX_USER);
      if (user_length >= 0)
        user[user_length] = 0;
      break;
    case 'v':
      log_level = strtol(optarg, NULL, 10);
      break;
    default:
      usage(argv[0], VERSION);
      exit(EXIT_FAILURE);
    }
  }

  coap_startup();
  coap_dtls_set_log_level(log_level);
  coap_set_log_level(log_level);
  dcaf_set_log_level(log_level);

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

#if 0
  dst.size = res;
  dst.addr.sin.sin_port = htons( port );

  session = get_session(
    ctx,
    node_str[0] ? node_str : NULL, NULL,
    uri.scheme==COAP_URI_SCHEME_COAPS ? COAP_PROTO_DTLS : COAP_PROTO_UDP,
    &dst,
    user_length > 0 ? (const char *)user : NULL,
    key_length > 0  ? key : NULL, (unsigned)key_length
  );

  if (!session) {
    dcaf_log(DCAF_LOG_EMERG, "cannot create client session\n");
    goto finish;
  }

  /* construct CoAP message */
  prepare_message(message_type);
  if (!(pdu = coap_new_request(ctx, session, method, &optlist, payload.s, payload.length))) {
    goto finish;
  }

  dcaf_log(DCAF_LOG_DEBUG, "sending CoAP request:\n");
  coap_show_pdu(LOG_INFO, pdu);
#endif
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

  if (!dcaf_send_request(dcaf, method, uri, strlen(uri), optlist, payload.s, payload.length, 0)) {
    dcaf_log(DCAF_LOG_EMERG, "cannot send request\n");
    exit(EXIT_FAILURE);
  }

  wait_ms = wait_seconds * 1000;
  dcaf_log(DCAF_LOG_DEBUG, "timeout is set to %u seconds\n", wait_seconds);

  while (!(ready && coap_can_exit(ctx))) {

    result = coap_run_once(ctx, wait_ms == 0 ? 1000 : min(wait_ms, 1000));

    if (result >= 0) {
      if (wait_ms > 0 && !wait_ms_reset) {
        if ((unsigned)result >= wait_ms) {
          dcaf_log(DCAF_LOG_INFO, "timeout\n");
          break;
        } else {
          wait_ms -= result;
        }
      }
    }
    wait_ms_reset = 0;
  }

  result = 0;

 finish:

  coap_delete_optlist(optlist);
  coap_session_release(session);
  dcaf_free_context(dcaf);
  coap_cleanup();
  close_output();

  return result;
}
