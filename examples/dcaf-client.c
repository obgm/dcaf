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
static coap_uri_t uri;

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
message_handler(struct coap_context_t *ctx,
                coap_session_t *session,
                coap_pdu_t *sent,
                coap_pdu_t *received,
                const coap_tid_t id UNUSED_PARAM) {

  coap_pdu_t *pdu = NULL;
  coap_opt_t *block_opt;
  coap_opt_iterator_t opt_iter;
  unsigned char buf[4];
  coap_optlist_t *option;
  size_t len;
  unsigned char *databuf;
  coap_tid_t tid;

#ifndef NDEBUG
  coap_log(LOG_DEBUG, "** process incoming %d.%02d response:\n",
           (received->code >> 5), received->code & 0x1F);
  coap_show_pdu(LOG_INFO, received);
#endif

  /* check if this is a response to our original request */
  if (!check_token(received)) {
    /* drop if this was just some message, or send RST in case of notification */
    if (!sent && (received->type == COAP_MESSAGE_CON ||
                  received->type == COAP_MESSAGE_NON))
      coap_send_rst(session, received);
    return;
  }

  if (received->type == COAP_MESSAGE_RST) {
    info("got RST\n");
    return;
  }

  /* output the received data, if any */
  if (COAP_RESPONSE_CLASS(received->code) == 2) {

    /* set obs timer if we have successfully subscribed a resource */
    if (!obs_started && coap_check_option(received, COAP_OPTION_OBSERVE, &opt_iter)) {
      coap_log(LOG_DEBUG,
               "observation relationship established, set timeout to %d\n",
               obs_seconds);
      obs_started = 1;
      obs_ms = obs_seconds * 1000;
      obs_ms_reset = 1;
    }

    /* Got some data, check if block option is set. Behavior is undefined if
     * both, Block1 and Block2 are present. */
    block_opt = coap_check_option(received, COAP_OPTION_BLOCK2, &opt_iter);
    if (block_opt) { /* handle Block2 */
      uint16_t blktype = opt_iter.type;

      /* TODO: check if we are looking at the correct block number */
      if (coap_get_data(received, &len, &databuf))
        append_to_output(databuf, len);

      if(COAP_OPT_BLOCK_MORE(block_opt)) {
        /* more bit is set */
        coap_log(LOG_DEBUG, "found the M bit, block size is %u, block nr. %u\n",
              COAP_OPT_BLOCK_SZX(block_opt),
              coap_opt_block_num(block_opt));

        /* create pdu with request for next block */
        pdu = coap_new_request(ctx, session, method, NULL, NULL, 0); /* first, create bare PDU w/o any option  */
        if ( pdu ) {
          /* add URI components from optlist */
          for (option = optlist; option; option = option->next ) {
            switch (option->number) {
              case COAP_OPTION_URI_HOST :
              case COAP_OPTION_URI_PORT :
              case COAP_OPTION_URI_PATH :
              case COAP_OPTION_URI_QUERY :
                coap_add_option(pdu, option->number, option->length,
                                option->data);
                break;
              default:
                ;     /* skip other options */
            }
          }

          /* finally add updated block option from response, clear M bit */
          /* blocknr = (blocknr & 0xfffffff7) + 0x10; */
          coap_log(LOG_DEBUG, "query block %d\n",
                   (coap_opt_block_num(block_opt) + 1));
          coap_add_option(pdu,
                          blktype,
                          coap_encode_var_safe(buf, sizeof(buf),
                                 ((coap_opt_block_num(block_opt) + 1) << 4) |
                                  COAP_OPT_BLOCK_SZX(block_opt)), buf);

          tid = coap_send(session, pdu);

          if (tid == COAP_INVALID_TID) {
            coap_log(LOG_DEBUG, "message_handler: error sending new request\n");
          } else {
	    wait_ms = wait_seconds * 1000;
	    wait_ms_reset = 1;
          }

          return;
        }
      }
    } else { /* no Block2 option */
      block_opt = coap_check_option(received, COAP_OPTION_BLOCK1, &opt_iter);

      if (block_opt) { /* handle Block1 */
        unsigned int szx = COAP_OPT_BLOCK_SZX(block_opt);
        unsigned int num = coap_opt_block_num(block_opt);
        coap_log(LOG_DEBUG,
                 "found Block1 option, block size is %u, block nr. %u\n",
                 szx, num);
        if (szx != block.szx) {
          unsigned int bytes_sent = ((block.num + 1) << (block.szx + 4));
          if (bytes_sent % (1 << (szx + 4)) == 0) {
            /* Recompute the block number of the previous packet given the new block size */
            block.num = (bytes_sent >> (szx + 4)) - 1;
            block.szx = szx;
            coap_log(LOG_DEBUG,
                     "new Block1 size is %u, block number %u completed\n",
                     (1 << (block.szx + 4)), block.num);
          } else {
            coap_log(LOG_DEBUG, "ignoring request to increase Block1 size, "
            "next block is not aligned on requested block size boundary. "
            "(%u x %u mod %u = %u != 0)\n",
                  block.num + 1, (1 << (block.szx + 4)), (1 << (szx + 4)),
                  bytes_sent % (1 << (szx + 4)));
          }
        }

        if (payload.length <= (block.num+1) * (1 << (block.szx + 4))) {
          coap_log(LOG_DEBUG, "upload ready\n");
          ready = 1;
          return;
        }

        /* create pdu with request for next block */
        pdu = coap_new_request(ctx, session, method, NULL, NULL, 0); /* first, create bare PDU w/o any option  */
        if (pdu) {

          /* add URI components from optlist */
          for (option = optlist; option; option = option->next ) {
            switch (option->number) {
              case COAP_OPTION_URI_HOST :
              case COAP_OPTION_URI_PORT :
              case COAP_OPTION_URI_PATH :
              case COAP_OPTION_CONTENT_FORMAT :
              case COAP_OPTION_URI_QUERY :
                coap_add_option(pdu, option->number, option->length,
                                option->data);
                break;
              default:
              ;     /* skip other options */
            }
          }

          /* finally add updated block option from response, clear M bit */
          /* blocknr = (blocknr & 0xfffffff7) + 0x10; */
          block.num++;
          block.m = ((block.num+1) * (1 << (block.szx + 4)) < payload.length);

          coap_log(LOG_DEBUG, "send block %d\n", block.num);
          coap_add_option(pdu,
                          COAP_OPTION_BLOCK1,
                          coap_encode_var_safe(buf, sizeof(buf),
                          (block.num << 4) | (block.m << 3) | block.szx), buf);

          coap_add_block(pdu,
                         payload.length,
                         payload.s,
                         block.num,
                         block.szx);
          coap_show_pdu(LOG_WARNING, pdu);

	  tid = coap_send(session, pdu);

          if (tid == COAP_INVALID_TID) {
            coap_log(LOG_DEBUG, "message_handler: error sending new request\n");
          } else {
	    wait_ms = wait_seconds * 1000;
	    wait_ms_reset = 1;
          }

          return;
        }
      } else {
        /* There is no block option set, just read the data and we are done. */
        if (coap_get_data(received, &len, &databuf))
          append_to_output(databuf, len);
      }
    }
  } else {      /* no 2.05 */

    /* check if an error was signaled and output payload if so */
    if (COAP_RESPONSE_CLASS(received->code) >= 4) {
      fprintf(stderr, "%d.%02d",
              (received->code >> 5), received->code & 0x1F);
      if (coap_get_data(received, &len, &databuf)) {
        fprintf(stderr, " ");
        while(len--)
        fprintf(stderr, "%c", *databuf++);
      }
      fprintf(stderr, "\n");
    }

  }

  /* any pdu that has been created in this function must be sent by now */
  assert(pdu == NULL);

  /* our job is done, we can exit at any time */
  ready = coap_check_option(received, COAP_OPTION_OBSERVE, &opt_iter) == NULL;
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
     "Usage: %s [-A CAM-Uri] [-a addr] [-k key] [-p port] \n"
     "\t\t [-u user] [-v verbosity] [method] URI\n\n"
     "\tURI can be an absolute URI or a URI prefixed with scheme and host.\n\n"
     "\tMethod can be any of GET|PUT|POST|DELETE|FETCH|PATCH|IPATCH. If no\n"
     "\tmethod was specified the default is GET.\n\n"
     "\t-a addr\t\tThe local interface address to use\n"
     "\t-k key \t\tPre-shared key for the specified user. This argument\n"
     "\t       \t\trequires (D)TLS with PSK to be available\n"
     "\t-p port\t\tListen on specified port\n"
     "\t-u user\t\tUser identity for pre-shared key mode. This argument\n"
     "\t       \t\trequires (D)TLS with PSK to be available\n"
     "\t-v num \t\tVerbosity level (default: %d)\n"
     "\t-A CAM\t\tURI of the client authorization manager\n"
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
 * Sets global URI options according to the URI passed as @p arg.
 * This function returns 0 on success or -1 on error.
 *
 * @param arg             The URI string.
 * @param create_uri_opts Flags that indicate whether Uri-Host and
 *                        Uri-Port should be suppressed.
 * @return 0 on success, -1 otherwise
 */
static int
cmdline_uri(char *arg, int create_uri_opts) {
  unsigned char portbuf[2];
#define BUFSIZE 40
  unsigned char _buf[BUFSIZE];
  unsigned char *buf = _buf;
  size_t buflen;
  int res;

  if (coap_split_uri((unsigned char *)arg, strlen(arg), &uri) < 0) {
    coap_log(LOG_ERR, "invalid CoAP URI\n");
    return -1;
  }

  if (uri.scheme==COAP_URI_SCHEME_COAPS && !reliable && !coap_dtls_is_supported()) {
    coap_log(LOG_EMERG,
             "coaps URI scheme not supported in this version of libcoap\n");
    return -1;
  }

  if ((uri.scheme==COAP_URI_SCHEME_COAPS_TCP || (uri.scheme==COAP_URI_SCHEME_COAPS && reliable)) && !coap_tls_is_supported()) {
    coap_log(LOG_EMERG,
             "coaps+tcp URI scheme not supported in this version of libcoap\n");
    return -1;
  }

  if (uri.port != get_default_port(&uri) && create_uri_opts) {
    coap_insert_optlist(&optlist,
                        coap_new_optlist(COAP_OPTION_URI_PORT,
                                         coap_encode_var_safe(portbuf, sizeof(portbuf),
                                                              (uri.port & 0xffff)),
                                         portbuf));
  }

  if (uri.path.length) {
    buflen = BUFSIZE;
    res = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);

    while (res--) {
      coap_insert_optlist(&optlist,
                          coap_new_optlist(COAP_OPTION_URI_PATH,
                                           coap_opt_length(buf),
                                           coap_opt_value(buf)));

      buf += coap_opt_size(buf);
    }
  }

  if (uri.query.length) {
    buflen = BUFSIZE;
    buf = _buf;
    res = coap_split_query(uri.query.s, uri.query.length, buf, &buflen);

    while (res--) {
      coap_insert_optlist(&optlist,
                          coap_new_optlist(COAP_OPTION_URI_QUERY,
                                           coap_opt_length(buf),
                                           coap_opt_value(buf)));

      buf += coap_opt_size(buf);
    }
  }

  return 0;
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
  char port_str[NI_MAXSERV] = "0";
  char node_str[NI_MAXHOST] = "";
  int opt, res;
  unsigned char user[MAX_USER + 1], key[MAX_KEY];
  ssize_t user_length = 0, key_length = 0;
  int create_uri_opts = 1;
  int message_type = -1;

  while ((opt = getopt(argc, argv, "a:k:p:u:v:A:M:")) != -1) {
    switch (opt) {
    case 'a':
      strncpy(node_str, optarg, NI_MAXHOST - 1);
      node_str[NI_MAXHOST - 1] = '\0';
      break;
    case 'k':
      key_length = cmdline_read_key(optarg, key, MAX_KEY);
      break;
    case 'p':
      strncpy(port_str, optarg, NI_MAXSERV - 1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    case 'A':
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
    if (cmdline_uri(argv[optind], create_uri_opts) < 0) {
      exit(1);
    }
  } else {
    usage(argv[0], VERSION);
    exit(EXIT_FAILURE);
  }

  if ((user_length < 0) || (key_length < 0)) {
    dcaf_log(DCAF_LOG_CRIT, "Invalid user name or key specified\n");
    goto finish;
  }
  
  server = uri.host;
  port = uri.port;

  /* resolve destination address where server should be sent */
  res = resolve_address(&server, &dst.addr.sa);

  if (res < 0) {
    dcaf_log(DCAF_LOG_CRIT, "failed to resolve address\n");
    exit(-1);
  }

  /* set random number generator function for DCAF library */
  dcaf_set_prng(rnd);

  dcaf = dcaf_new_context(&config);

  if (!dcaf || !(ctx = dcaf_get_coap_context(dcaf)))
    return 2;

  dst.size = res;
  dst.addr.sin.sin_port = htons( port );

  session = get_session(
    ctx,
    node_str[0] ? node_str : NULL, port_str,
    uri.scheme==COAP_URI_SCHEME_COAPS ? COAP_PROTO_DTLS : COAP_PROTO_UDP,
    &dst,
    user_length > 0 ? (const char *)user : NULL,
    key_length > 0  ? key : NULL, (unsigned)key_length
  );

  if (!session) {
    dcaf_log(DCAF_LOG_EMERG, "cannot create client session\n");
    goto finish;
  }

  coap_register_response_handler(ctx, message_handler);

  /* construct CoAP message */
  prepare_message(message_type);
  if (!(pdu = coap_new_request(ctx, session, method, &optlist, payload.s, payload.length))) {
    goto finish;
  }

  dcaf_log(DCAF_LOG_DEBUG, "sending CoAP request:\n");
  coap_show_pdu(LOG_INFO, pdu);

  coap_send(session, pdu);

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
