/* s -- CoAP resource server with authenticated authorization
 *
 * Copyright (c) 2016-2021 Olaf Bergmann <bergmann@tzi.org>
 *               2016-2021 Stefanie Gerdes <gerdes@tzi.org>
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

#define MAX_KEY   64 /* Maximum length of a key (i.e., PSK) in bytes. */
#define MAX_RESOURCE_BUF 1024

static const char r_restricted[] = "restricted";
static const char r_ticket[] = "ticket";
static const char r_am_info[] = "am-info";

static char resource_buf[MAX_RESOURCE_BUF] =
  "This is a resource with restricted access.\n";
static size_t resource_len = 43;

/* handler for requests to a resource with restricted access */
static void
hnd_get(coap_context_t *ctx,
        struct coap_resource_t *resource,
        coap_session_t *session,
        coap_pdu_t *request,
        coap_binary_t *token,
        coap_string_t *query,
        coap_pdu_t *response) {
  unsigned char buf[3];
  (void)ctx;
  (void)resource;
  (void)token;
  (void)query;

  /* Check if authorized, i.e., the request was received on a secure
   * channel. */
  if (!dcaf_is_authorized(session, request)) {
    dcaf_result_t res;
    res = dcaf_set_sam_information(session, DCAF_MEDIATYPE_DCAF_CBOR,
                                   response);
    if (res != DCAF_OK) {
      coap_log(LOG_WARNING, "cannot create SAM Information %d\n", res);
    }
    return;
  }
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);

  coap_add_option(response,
                  COAP_OPTION_CONTENT_TYPE,
                  coap_encode_var_safe(buf, sizeof(buf),
                                       COAP_MEDIATYPE_TEXT_PLAIN),
                  buf);

  coap_add_data(response, resource_len, (const uint8_t *)resource_buf);
}

/* handler for uploads to the ticket resource */
static void
hnd_ticket_post(coap_context_t *ctx,
        struct coap_resource_t *resource,
        coap_session_t *session,
        coap_pdu_t *request,
        coap_binary_t *token,
        coap_string_t *query,
        coap_pdu_t *response) {
  size_t size;
  dcaf_result_t res;
  const uint8_t *data;
  dcaf_ticket_t *ticket;
  (void)ctx;
  (void)resource;
  (void)token;
  (void)query;

  coap_get_data(request,&size, &data);
  if (size == 0) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
    return;
  }
  res = dcaf_parse_ticket_face(session, data, size, &ticket);
  if (res == DCAF_ERROR_BAD_REQUEST) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
    return;
    /* FIXME: handle other errors */
  }
  dcaf_add_ticket(ticket);
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
}

static void
hnd_am_info_get(coap_context_t *ctx,
        struct coap_resource_t *resource,
        coap_session_t *session,
        coap_pdu_t *request,
        coap_binary_t *token,
        coap_string_t *query,
        coap_pdu_t *response) {
  (void)ctx;
  (void)resource;
  (void)request;
  (void)token;
  (void)query;

  dcaf_result_t res;
  res = dcaf_set_sam_information(session, DCAF_MEDIATYPE_DCAF_CBOR,
				 response);
  if (res != DCAF_OK) {
    coap_log(LOG_WARNING, "cannot create SAM Information %d\n", res);
  }
  return;
}


static void
init_resources(coap_context_t *ctx) {
  coap_resource_t *r;
  /* initialize the resource for uploading tickets */
  r = coap_resource_init(coap_make_str_const(r_ticket), 0);
  coap_register_handler(r, COAP_REQUEST_POST, hnd_ticket_post);
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("75"), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("dcaf-ticket"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"ticket resource\""), 0);
  coap_add_resource(ctx, r);

  /* initialize a resource with restricted access */
  r = coap_resource_init(coap_make_str_const(r_restricted), 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"restricted access\""), 0);
  coap_add_resource(ctx, r);
  r = coap_resource_init(coap_make_str_const(r_am_info), 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_am_info_get);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("am-info"), 0);
    coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"SAM information resource\""), 0);
  coap_add_resource(ctx, r);
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
usage(const char *program, const char *version) {
  const char *p;

  p = strrchr(program, '/');
  if ( p )
    program = ++p;

  fprintf(stderr, "%s v%s -- a CoAP server with authenticated authorization\n"
     "Copyright (c) 2016-2021 Olaf Bergmann <bergmann@tzi.org>\n\n"
     "usage: %s [-A address] [-a URI] [-k key] [-p port] [-v num]\n\n"
     "\t-A address\tinterface address to bind to\n"
     "\t-a URI\t\tauthorization manager (AM) URI (the \"token endpoint\")\n"
     "\t-k key\t\tAM shared secret\n"
     "\t-p port\t\tlisten on specified port\n"
     "\t-v num\t\tverbosity level (default: 3)\n",
     program, version, program );
}

static void
rnd(uint8_t *out, size_t len) {
#ifdef HAVE_GETRANDOM
  if (getrandom(out, len, 0) < 0) {
    dcaf_log(LOG_WARN, "getrandom failed: %s", strerror(errno));
  }
#else /* HAVE_GETRANDOM */
  /* FIXME: need to set a useful seed with srandom() */
#define min(a,b) (((a) < (b)) ? (a) : (b))
  typedef long int rand_t;

  for (; len; len -= sizeof(rand_t), out += sizeof(rand_t)) {
    rand_t v = random();
    memcpy(out, &v, min(len, sizeof(rand_t)));
  }
#undef min
#endif /* HAVE_GETRANDOM */
}

int
main(int argc, char **argv) {
  dcaf_context_t  *dcaf;
  coap_context_t  *ctx;
  char addr_str[NI_MAXHOST] = "::";
  int opt, result = 0;
  union {
    coap_log_t coap;
    dcaf_log_t dcaf;
  } log_level = { .dcaf = DCAF_LOG_WARNING };
  dcaf_config_t config;
  unsigned char key[MAX_KEY];
  ssize_t key_length = 0;

  memset(&config, 0, sizeof(config));
  config.host = addr_str;
  config.coap_port = COAP_DEFAULT_PORT;
  config.coaps_port = COAPS_DEFAULT_PORT;

  while ((opt = getopt(argc, argv, "A:a:k:p:v:")) != -1) {
    switch (opt) {
    case 'A' :
      strncpy(addr_str, optarg, NI_MAXHOST-1);
      addr_str[NI_MAXHOST - 1] = '\0';
      break;
    case 'a' :
      /* FIXME: check if URI has correct format */
      config.am_uri = optarg;
      break;
    case 'k' :
      key_length = cmdline_read_key(optarg, key, MAX_KEY);
      break;
    case 'p' :
      config.coap_port = (uint16_t)strtol(optarg, NULL, 10);
      config.coaps_port = config.coap_port + 1;
      break;
    case 'v' :
      log_level.dcaf = strtol(optarg, NULL, 10);
      break;
    default:
      usage(argv[0], VERSION);
      exit(1);
    }
  }

  coap_startup();
  coap_dtls_set_log_level(log_level.coap);
  coap_set_log_level(log_level.coap);
  dcaf_set_log_level(log_level.dcaf);

  /* set random number generator function for DCAF library */
  dcaf_set_prng(rnd);

  dcaf = dcaf_new_context(&config);

  if (!dcaf || !(ctx = dcaf_get_coap_context(dcaf)))
    return 2;

  /* set AM key when specified */
  if (key_length > 0) {
    dcaf_key_t *k = dcaf_new_key(DCAF_AES_128);
    if (!k) {
      dcaf_log(DCAF_LOG_CRIT, "cannot set AM key\n");
      dcaf_free_context(dcaf);
      return 3;
    }
    dcaf_set_key(k, key, key_length);
    dcaf_add_key(dcaf, dcaf_get_am_address(dcaf), k);
    
    /* set default key for incoming requests from SAM */
    coap_context_set_psk(ctx, "SAM", key, key_length);
  }

  init_resources(ctx);

  while (true) {
#if !defined(LIBCOAP_VERSION) || (LIBCOAP_VERSION < 4003000)
    coap_run_once(ctx, 0);
#else /* LIBCOAP_VERSION >= 4003000 */
    coap_io_process(ctx, COAP_IO_WAIT);
#endif  /* LIBCOAP_VERSION >= 4003000 */
    /* regularly check tickets, deprecated tickets and nonces if they
       are expired */
    dcaf_expiration();
  }

  dcaf_free_context(dcaf);
  coap_cleanup();

  return result;
}
