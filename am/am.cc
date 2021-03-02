/*
 * am.cc -- DCAF authorization manager
 *
 * Copyright (C) 2015-2021 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2021 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 *
 * Parts of the server code are taken from the libcoap server example.
 */

#include <algorithm>
#include <random>
#include <string>
#include <type_traits>

#include <fstream>
#include <iostream>
#include <iomanip>
#include <memory>

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>

#include <coap2/coap.h>
#include <coap2/coap_dtls.h>

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_am.h"
#include "config_parser.hh"

#define COAP_RESOURCE_CHECK_TIME 2

static void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr(program, '/');
  if (p)
    program = ++p;

  fprintf( stderr, "%s v%s -- DCAF Authorization Server\n"
           "(c) 2015-2021 Olaf Bergmann <bergmann@tzi.org>\n"
           "(c) 2015-2021 Stefanie Gerdes <gerdes@tzi.org>\n\n"
           "usage: %s [-A address] [-a uri] [-C file] [-p port] [-v num]\n\n"
           "\t-A address\tinterface address to bind to\n"
           "\t-a URI\t\tauthorization manager (AM) URI (the \"token endpoint\")\n"
           "\t-C file\t\tload configuration file\n"
           "\t-p port\t\tlisten on specified port\n"
           "\t-v num\t\tverbosity level (default: 3)\n",
    program, version, program );
}

/* Set to true if SIGINT or SIGTERM are caught. The main loop will
 * exit gracefully if quit == true. */
static bool quit = false;

/* SIGINT handler: set quit to 1 for graceful termination */
static void
handle_sigint(int signum) {
  (void)signum;
  quit = true;
}

/* TODO: store issued tickets until they become invalid */

static void
hnd_post_token(coap_context_t *ctx,
              struct coap_resource_t *resource,
              coap_session_t *session,
              coap_pdu_t *request,
              coap_binary_t *token,
              coap_string_t *query,
              coap_pdu_t *response) {
  dcaf_ticket_request_t *treq = NULL;
  dcaf_result_t res;

  (void)ctx;
  (void)resource;
  (void)token;
  (void)query;

  /* Check if authorized, i.e., the request was received on a secure
   * channel. */
  // if (!dcaf_is_authorized(session, request)) {
  //   dcaf_set_sam_information(session, DCAF_MEDIATYPE_DCAF_CBOR,
  //                            response);
  //   return;
  // }
  res = dcaf_parse_ticket_request(session, request, &treq);
  if (res != DCAF_OK) {
    (void)dcaf_set_error_response(session, res, response);
    return;
  }

  dcaf_set_ticket_grant(session, treq, response);
}

static void
hnd_unknown(coap_context_t *ctx,
            struct coap_resource_t *resource,
            coap_session_t *session,
            coap_pdu_t *request,
            coap_binary_t *token,
            coap_string_t *query,
            coap_pdu_t *response) {
  coap_string_t *uri_path;
  (void)ctx;
  (void)resource;
  (void)session;
  (void)token;
  (void)query;

  /* the default response code */
  response->code = COAP_RESPONSE_CODE_NOT_FOUND;
  uri_path = coap_get_uri_path(request);
  if (!uri_path) {
    return;
  }

  std::string_view uri(reinterpret_cast<const char *>(uri_path->s), uri_path->length);
  if ((coap_get_method(request) == COAP_REQUEST_PUT)) {
    if (uri.substr(0, 4) == "key/") {
      /* FIXME: read payload as key and add to key store */
      dcaf_log(DCAF_LOG_DEBUG, "a key!\n");
      response->code = COAP_RESPONSE_CODE_CREATED;
    }
  }
}

static void
init_resources(coap_context_t *coap_context) {
  coap_resource_t *resource;
  const char mediatypes[] = DCAF_MEDIATYPE_DCAF_CBOR_STRING " " DCAF_MEDIATYPE_ACE_CBOR_STRING;

  resource = coap_resource_init(coap_make_str_const(DCAF_AM_DEFAULT_PATH), 0);
  coap_register_handler(resource, COAP_REQUEST_POST, hnd_post_token);
  /* add values for supported content-formats */
  coap_add_attr(resource, coap_make_str_const("ct"),
                coap_make_str_const(mediatypes), 0);
  coap_add_resource(coap_context, resource);

  resource = coap_resource_unknown_init(hnd_unknown);
  if (resource) {
    coap_register_handler(resource, COAP_REQUEST_POST, hnd_unknown);
    coap_add_resource(coap_context, resource);
  }
}

static void
rnd(uint8_t *out, size_t len) {
  static std::random_device rd;
  static std::seed_seq seed{rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()};
  static std::mt19937 generate(seed);
  using rand_t = uint32_t;
  static std::uniform_int_distribution<rand_t> rand;

  while (len) {
    rand_t v = rand(generate);
    size_t count = std::min(len, sizeof(rand_t));
    memcpy(out, &v, count);
    len -= count;
    out += count;
  }
}

static const uint8_t *cast(const char *p) {
  static_assert(std::is_same<unsigned char, uint8_t>::value, "uint8_t is not unsigned char");
  return reinterpret_cast<const uint8_t *>(p);
}

static dcaf_key_t *
make_key(const std::string &id, const am_config::parser::key_type &type) {
  if (std::get<0>(type) == am_config::parser::key_t::PSK) {
    dcaf_key_t *key = dcaf_new_key(DCAF_AES_128);
    if (dcaf_set_key(key,
                     cast(std::get<1>(type).c_str()),
                     std::get<1>(type).length()) &&
        dcaf_set_kid(key, cast(id.c_str()), id.length())) {
      return key;
    } else {
      dcaf_delete_key(key);
    }
  }
  return nullptr;
}

int
main(int argc, char **argv) {
  dcaf_context_t  *dcaf;
  coap_context_t  *ctx;
  std::string addr_str = "::1";
  int opt;
  coap_log_t log_level = LOG_WARNING;
  unsigned wait_ms;
  dcaf_config_t config;
  am_config::parser parser;
  struct sigaction sa;

  memset(&config, 0, sizeof(config));
  config.host = addr_str.c_str();
  config.coap_port = DCAF_DEFAULT_COAP_PORT;
  config.coaps_port = DCAF_DEFAULT_COAPS_PORT;

  while ((opt = getopt(argc, argv, "a:A:C:g:p:v:l:")) != -1) {
    switch (opt) {
    case 'A':
      config.host = optarg;
      break;
    case 'a' :
      config.am_uri = optarg;
      break;
    case 'C' : {
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
      usage(argv[0], LIBDCAF_PACKAGE_VERSION);
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

  /* fill key store */
  std::for_each(parser.keys.cbegin(), parser.keys.cend(),
                [&dcaf](auto const &k) {
                  dcaf_key_t *key = make_key(k.first, k.second);
                  if (key) {
                    std::cout << std::quoted(k.first) << " \u2192 "
                              << std::quoted(std::get<1>(k.second)) << std::endl;
                    dcaf_add_key(dcaf, nullptr, key);
                  }
                });
  init_resources(ctx);

  memset (&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = handle_sigint;
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

  while (!quit) {
    int result;
#if !defined(LIBCOAP_VERSION) || (LIBCOAP_VERSION < 4003000)
    result = coap_run_once(ctx, wait_ms);
#else /* LIBCOAP_VERSION >= 4003000 */
    result = coap_io_process(ctx, wait_ms);
#endif  /* LIBCOAP_VERSION >= 4003000 */
    if ( result < 0 ) {
      break;
    } else if ((unsigned)result < wait_ms) {
      wait_ms -= result;
    } else {
      wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
    }
  }

  dcaf_free_context(dcaf);
  coap_cleanup();

  return 0;
}
