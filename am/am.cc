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

#include <fstream>
#include <iostream>

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <ctype.h>
#include <unistd.h>

#include <coap/coap.h>
#include <coap/coap_dtls.h>

#include "dcaf/dcaf.h"
#include "config_parser.hh"

#define COAP_RESOURCE_CHECK_TIME 2

static void
fill_keystore(coap_context_t *ctx) {
  //static uint8_t key[] = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  dcaf_time_t now = dcaf_gettime();
  dcaf_ticket_t *ticket = dcaf_new_ticket((uint8_t *)"CoAP", 4, (uint8_t *)"secretPSK", 9, 265, now, 3600);
  (void)ctx;

  dcaf_add_ticket(ticket);
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
              coap_binary_t *token,
              coap_string_t *query,
              coap_pdu_t *response) {
  dcaf_authz_t *authz;
  dcaf_result_t res;

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

  res = dcaf_parse_ticket_request(session, request, &authz);
  if (res != DCAF_OK) {
    (void)dcaf_set_error_response(session, res, response);
    return;
  }

  dcaf_set_ticket_grant(session, authz, response);
  dcaf_delete_authz(authz);
}

static void
init_resources(coap_context_t *coap_context) {
  coap_resource_t *resource;
  const char mediatypes[] = DCAF_MEDIATYPE_DCAF_CBOR_STRING " " DCAF_MEDIATYPE_ACE_CBOR_STRING;

  resource = coap_resource_init(coap_make_str_const(DCAF_TOKEN_DEFAULT), 0);
  coap_register_handler(resource, COAP_REQUEST_POST, hnd_post_token);
  /* add values for supported content-formats */
  coap_add_attr(resource, coap_make_str_const("ct"),
                coap_make_str_const(mediatypes), 0);
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

  while ((opt = getopt(argc, argv, "A:C:g:p:v:l:")) != -1) {
    switch (opt) {
    case 'A' :
      config.host = optarg;
      break;
    case 'C' : {
      am_config::parser parser;
      std::fstream cf(optarg, std::ios_base::in);
      if (!cf) {
        std::cerr << "Cannot open config file '" << optarg << "'" << std::endl;
        exit(2);
      }
      try {
        if (!parser.parse(cf)) {
          std::cerr << "Invalid configuration!" << std::endl;
          exit(3);
        }
      } catch (lug::lug_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        exit(3);
      }
      std::cout << "configured keys: " << std::endl;
      for (auto k : parser.keys) {
        std::cout << "\"" << k.first << "\" => \"" << std::get<1>(k.second) << "\"" << std::endl;
      }

      break;
    }
    case 'p' :
      config.coap_port = static_cast<uint16_t>(strtol(optarg, nullptr, 10));
      config.coaps_port = config.coap_port + 1;
      break;
    case 'v' :
      log_level = static_cast<coap_log_t>(strtol(optarg, nullptr, 10));
      break;
    default:
      usage(argv[0], LIBCOAP_PACKAGE_VERSION);
      exit(1);
    }
  }

  coap_startup();
  coap_dtls_set_log_level(log_level);
  coap_set_log_level(log_level);
  dcaf_set_log_level((dcaf_log_t)log_level);

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
