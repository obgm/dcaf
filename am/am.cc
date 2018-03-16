/*
 * as.cc -- DCAF authorization manager
 *
 * Copyright (C) 2015-2018 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2018 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 *
 * Parts of the server code are taken from the libcoap server example.
 */

#include <algorithm>
#include <random>
#include <string>

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <ctype.h>
#include <unistd.h>

#include <coap/coap.h>
#include <coap/coap_dtls.h>

#include "dcaf/dcaf.h"

#define COAP_RESOURCE_CHECK_TIME 2

static void
fill_keystore(coap_context_t *ctx) {
  static uint8_t key[] = "secretPSK";
  size_t key_len = sizeof(key) - 1;
  coap_context_set_psk(ctx, "DCAF user", key, key_len);
}

static void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr(program, '/');
  if (p)
    program = ++p;

  fprintf( stderr, "%s v%s -- DCAF Authorization Server\n"
           "(c) 2015-2018 Olaf Bergmann <bergmann@tzi.org>\n\n"
           "(c) 2015-2018 Stefanie Gerdes <gerdes@tzi.org>\n\n"
           "usage: %s [-A address] [-p port]\n\n"
           "\t-A address\tinterface address to bind to\n"
           "\t-p port\t\tlisten on specified port\n"
           "\t-v num\t\tverbosity level (default: 3)\n",
    program, version, program );
}

static void
hnd_post_token(coap_context_t *ctx,
              struct coap_resource_t *resource,
              coap_session_t *session,
              coap_pdu_t *request,
              str *token,
              str *query,
              coap_pdu_t *response) {
  dcaf_authz_t *authz;

  (void)ctx;
  (void)resource;
  (void)token;
  (void)query;

  /* Check if authorized, i.e., the request was received on a secure
   * channel. */
  if (!dcaf_is_authorized(session, request)) {
    dcaf_set_sam_information(session, DCAF_MEDIATYPE_DCAF_CBOR,
                             response);
    return;
  }

  authz = dcaf_parse_authz_request(session, request);
  if (!authz) {
    (void)dcaf_set_error_response(session, DCAF_ERROR_BAD_REQUEST, response);
    return;
  }

  dcaf_set_ticket_grant(session, authz, response);
}

static void
init_resources(coap_context_t *coap_context) {
  coap_resource_t *resource;
  const unsigned char *token = (const unsigned char *)DCAF_TOKEN_DEFAULT;
  size_t token_len = sizeof(DCAF_TOKEN_DEFAULT) - 1;
  const char mediatypes[] = DCAF_MEDIATYPE_DCAF_CBOR_STRING " " DCAF_MEDIATYPE_ACE_CBOR_STRING;

  resource = coap_resource_init(token, token_len, 0);
  coap_register_handler(resource, COAP_REQUEST_POST, hnd_post_token);
  /* add values for supported content-formats */
  coap_add_attr(resource, (unsigned char *)"ct", 2,
                (unsigned char *)mediatypes,
                sizeof(mediatypes) - 1,
                0);
  coap_add_resource(coap_context, resource);
}

static void
rnd(uint8_t *out, size_t len) {
  static std::random_device rd;
  static std::seed_seq seed{rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()};
  static std::mt19937 generate(seed);
  using rand_t = uint32_t;
  static std::uniform_int_distribution<rand_t> rand;

  for (; len; len -= sizeof(rand_t), out += sizeof(rand_t)) {
    rand_t v = rand(generate);
    memcpy(out, &v, std::min(len, sizeof(rand_t)));
  }
}

int
main(int argc, char **argv) {
  dcaf_context_t  *dcaf;
  coap_context_t  *ctx;
  std::string addr_str = "::";
  int opt;
  coap_log_t log_level = LOG_WARNING;
  unsigned wait_ms;
  dcaf_config_t config;

  memset(&config, 0, sizeof(config));
  config.host = addr_str.c_str();

  while ((opt = getopt(argc, argv, "A:g:p:v:l:")) != -1) {
    switch (opt) {
    case 'A' :
      config.host = optarg;
      break;
    case 'p' :
      config.coap_port = static_cast<uint16_t>(strtol(optarg, nullptr, 10));
      config.coaps_port = config.coap_port + 1;
      break;
    case 'v' :
      log_level = static_cast<coap_log_t>(strtol(optarg, nullptr, 10));
      break;
    default:
      usage( argv[0], LIBCOAP_PACKAGE_VERSION );
      exit( 1 );
    }
  }

  coap_startup();
  coap_dtls_set_log_level(log_level);
  coap_set_log_level(log_level);

  /* set random number generator function for DCAF library */
  dcaf_set_prng(rnd);

  dcaf = dcaf_new_context(&config);
  if (!dcaf || !(ctx = dcaf_get_coap_context(dcaf)))
    return -1;

  fill_keystore(ctx);
  init_resources(ctx);

  wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

  while (true) {
    int result = coap_run_once(ctx, wait_ms);
    if ( result < 0 ) {
      break;
    } else if ((unsigned)result < wait_ms) {
      wait_ms -= result;
    } else {
      wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
    }

    /* check if we have to send observe notifications */
    coap_check_notify(ctx);
  }

  dcaf_free_context(dcaf);
  coap_cleanup();

  return 0;
}
