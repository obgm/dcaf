/*
 * dcaf_am_test_client.cc -- test client for the DCAF authorization manager using attribute-based credentials
 *
 * Copyright (C) 2018-2019 Sara Stadler
 *
 * This file is part of the DCAF library libdcaf. Please see README
 *
 *  Parts of the code are taken from the dcaf_client.
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

#include <coap2/coap.h>
#include <coap2/coap_dtls.h>

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "am_util.hh"




dcaf_config_t config = {"::",0,0, "coap://localhost"};

/* The log level (may be changed with option '-v' on the command line. */
coap_log_t log_level = LOG_NOTICE;

/* Request URI.*/
const char *uri = NULL;

/*URI of SAM the request should be forwarded to*/
const char *sam_uri = NULL;

typedef unsigned char method_t;


static void usage(const char *program) {

	fprintf( stderr,
			"DCAF example client\n"
					"Usage: %s [-A address] [-p port] [-R resource] -s sam_uri URI\n\n"
					"\tURI can be an absolute URI or a URI prefixed with scheme and host.\n\n"
					"\t-A address\tInterface address to bind to\n"
					"\t-p port\t\tListen on specified port\n"
					"\t-R resource\taccess specific resource on S \n"
					"\t-s SAM\t\tURI of the sever authorization manager the ticket request will be forwarded to\n"
					"\t-v num\t\tverbosity level (default: 5)\n\n",
			program);
}




/*
 * Creates a ticket request for the given resource containing the URI of the SAM
 * to forward the request to.
 */
static dcaf_result_t
prepare_ticket_request(coap_pdu_t *pdu, const char *resource) {
  static uint8_t buf[1024];
  cn_cbor *cbor = NULL;
    cn_cbor *scope;
    int length;
    unsigned char optionbuf[18];

    /* set payload */
    cbor = cn_cbor_map_create(NULL);
    cn_cbor_mapput_int(cbor, DCAF_TICKET_ISS,
                       cn_cbor_string_create("foo", NULL),
                       NULL);
    cn_cbor_mapput_int(cbor, DCAF_TICKET_AUD,
                       cn_cbor_string_create(sam_uri, NULL),
                       NULL);
    scope = cn_cbor_array_create(NULL);
    cn_cbor_array_append(scope, cn_cbor_string_create(resource, NULL), NULL);
    cn_cbor_array_append(scope, cn_cbor_int_create(1, NULL), NULL);
    cn_cbor_mapput_int(cbor, DCAF_TICKET_SCOPE, scope, NULL);

	length = cn_cbor_encoder_write(buf, 0, sizeof(buf), cbor);
	cn_cbor_free(cbor);

	if (length == 0)
		return DCAF_ERROR_INTERNAL_ERROR;

	pdu->code = COAP_REQUEST_POST;

	//set options
	coap_add_option(pdu, COAP_OPTION_URI_PATH, strlen(DCAF_AM_DEFAULT_PATH),
			(const uint8_t *) DCAF_AM_DEFAULT_PATH);

	coap_add_option(pdu,
	COAP_OPTION_CONTENT_FORMAT,
			coap_encode_var_safe(optionbuf, sizeof(optionbuf),
					DCAF_MEDIATYPE_DCAF_CBOR), optionbuf);

	coap_add_option(pdu,
	COAP_OPTION_MAXAGE, coap_encode_var_safe(optionbuf, sizeof(optionbuf), 90),
			optionbuf);

	coap_add_data(pdu, length, buf);

	dcaf_log(DCAF_LOG_INFO, "create message \n");
	dcaf_debug_hexdump(buf, length);

	return DCAF_OK;

}

/*
 * Handler for ticket transfer message from SAM.
 */
static void hnd_ticket_response(coap_context_t *ctx,
		coap_session_t *session,
		coap_pdu_t *sent, coap_pdu_t *received, const coap_tid_t id){

	dcaf_log(DCAF_LOG_INFO, "hnd_ticket_response\n");
	(void)ctx;
	(void)sent;
	(void)id;
	(void)received;

	dcaf_log(DCAF_LOG_NOTICE, "Received response\n");
	coap_show_pdu(LOG_NOTICE, received);


	if(received->code != COAP_RESPONSE_CODE(200)){
		set_transaction_state(session, DCAF_STATE_UNAUTHORIZED);
		return;
	}

	set_transaction_state(session, DCAF_STATE_TICKET_GRANT);
}

int
main(int argc, char **argv) {
	dcaf_context_t *dcaf = NULL;
	coap_context_t *ctx;
	coap_session_t *session = NULL;
	int result = -1;
	char node_str[NI_MAXHOST] = "";
	int opt;
	dcaf_transaction_t *t;
	coap_pdu_t *pdu;
	coap_address_t dst;
	const char *resource = "127.0.0.1/family";

	while ((opt = getopt(argc, argv, "p:v:A:s:R:")) != -1) {
		switch (opt) {
		case 'A':
			strncpy(node_str, optarg, NI_MAXHOST - 1);
			node_str[NI_MAXHOST - 1] = '\0';
			;
			break;
		case 'p':
			config.coap_port = atoi(optarg);
			config.coaps_port = config.coap_port + 1;
			break;
		case 'v':
			log_level = static_cast<coap_log_t>(strtol(optarg, nullptr, 10));
			break;
		case 's':
			sam_uri = optarg;
			break;
		case 'R':
			resource = optarg;
			break;
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	coap_startup();
	coap_dtls_set_log_level(log_level);
	coap_set_log_level(log_level);
	dcaf_set_log_level((dcaf_log_t) log_level);

	if (optind < argc) {
		uri = argv[optind];
	} else {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	if(sam_uri == NULL){
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* set random number generator function for DCAF library */
	dcaf_set_prng(rnd);

	dcaf = dcaf_new_context(&config);

	if (!dcaf || !(ctx = dcaf_get_coap_context(dcaf)))
		return 2;

	//register response handler
	coap_register_response_handler(ctx, hnd_ticket_response);

	if (resolve_address(uri, &dst) != DCAF_OK) {
		goto finish;
	}

	session = coap_new_client_session(ctx, nullptr, &dst, COAP_PROTO_UDP);
	if (!session) {
		dcaf_log(DCAF_LOG_EMERG,
				"Cannot create client session\n");
		goto finish;
	}

	pdu = generate_pdu(session);

	/* construct CoAP message */
	if(prepare_ticket_request(pdu, resource)!= DCAF_OK){
		dcaf_log(DCAF_LOG_ERR,
						"Cannot create message\n");
				goto finish;
	}


	t = dcaf_create_transaction(dcaf, session, pdu);
	if (!t) {
		dcaf_log(DCAF_LOG_WARNING, "cannot create new transaction\n");
		goto finish;
	}

	dcaf_log(DCAF_LOG_INFO, "sending CoAP request!\n");
	coap_show_pdu(LOG_INFO, pdu);

	coap_send(session, pdu);
	run_and_wait(ctx, session, 90);

	result = 0;

	finish:

	if (session != NULL) {
		coap_session_release(session);
	}
	dcaf_free_context(dcaf);
	coap_cleanup();

	return result;
}
