/*
 * Created by Sara Stadler 2018/2019
 *
 * Parts of the code are taken from the libcoap client and server examples.
 * Parts of the code are taken from the dcaf am example.
 */


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
#include <jansson.h>
#include <netdb.h>


#include <coap2/coap.h>
#include <coap2/coap_dtls.h>


#include "dcaf/dcaf.h"
#include "dcaf/dcaf_am.h"
#include "dcaf/dcaf_abc.h"
#include "dcaf/dcaf_abc_json.h"
#include "dcaf/dcaf_rules.h"
#include "dcaf/dcaf_rules_json.h"
#include "dcaf/dcaf_directory_traverser.h"

#include "am_util.hh"

/*
 * The type of the AM is determined when reading the abc configuration.
 */
dcaf_am_type_t type = DCAF_UNKNOWN_AM;

coap_resource_t *default_resource = NULL;
coap_resource_t *ticket_resource = NULL;
coap_resource_t *proof_resource = NULL;

dcaf_config_t config;
am_abc_configuration_st *abc_config = NULL;
json_t *abc_config_json = NULL;

rule_list_st *rules = NULL;
attribute_rule_list_st *attribute_rules = NULL;
credential_list_st *credential_descriptions;
credential_store_st *credential_store;
coap_dtls_pki_t* pki_sam = NULL;

/* Set to true if SIGINT or SIGTERM are caught. The main loop will
 * exit gracefully if quit == true. */
static bool quit = false;



static void
init_resources(coap_context_t *coap_context);


static void hnd_attribute_info(coap_context_t *ctx, coap_session_t *session,
		coap_pdu_t *sent, coap_pdu_t *received, const coap_tid_t id);

static void hnd_ticket_response(coap_context_t *ctx, coap_session_t *session,
		coap_pdu_t *sent, coap_pdu_t *received, const coap_tid_t id);



static void
usage( const char *program) {
  const char *p;

  p = strrchr(program, '/');
  if (p)
    program = ++p;

  fprintf( stderr, "DCAF Authorization Server\n"
           "usage: %s -c abc configuration [-A address] [-p port] [-v verbosity] [-C config]\n\n"
           "\t-A address\tinterface address to bind to\n\n"
		  "\t-c config\tjson file to load abc configuration from from\n\n"
		  "\t-p port\t\tlisten on specified port\n\n"
           "\t-v num\t\tverbosity level (default: 3)\n\n",
		   program);
}


/* SIGINT handler: set quit to 1 for graceful termination */
static void
handle_sigint(int signum) {
  dcaf_log(DCAF_LOG_INFO, "handle_sigint\n");
  (void)signum;
  quit = true;
}


/*Loads the rule list specified by path into global rules.
 * On success memory for global rules is allocated and has to be freed on
 * cleanup.
 * */
static dcaf_result_t
load_rule_list(const char *path){
	dcaf_result_t ret;
	json_error_t error;
	json_t *j;
	j = json_load_file(path, 0, &error);
	if(j == NULL){
		dcaf_log(DCAF_LOG_ERR,"load_rule_list: Failed to load rulelist: %s %s\n", path, error.text);
		json_decref(j);
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	ret = json_to_rule_list(j, &rules);
	json_decref(j);
	return ret;
}

/* Loads the attribute rules list specified by path into global attribute_rules.
 * On success memory for global attribute_rules is allocated and has to be freed on
 * cleanup.
 */
static dcaf_result_t
load_attribute_rule_list(const char *path){
	dcaf_result_t ret;
	json_error_t error;
	json_t *j;
	j = json_load_file(path, 0, &error);
	if(j == NULL){
		dcaf_log(DCAF_LOG_ERR,"load_attribute_rule_list: Failed to load attribute rulelist: %s %s\n", path, error.text);
		json_decref(j);
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	ret = json_to_attribute_rule_list(j, &attribute_rules);
	json_decref(j);
	return ret;
}

/*loads the abc configuration specified by path into global abc_config.
 * On success memory for global abc_config such as global abc_config_json
 * is allocated and has to be freed on cleanup.
 * */
static dcaf_result_t
load_am_ab_configuration(const char *path){
	dcaf_result_t res;
	json_error_t error;
	abc_config_json = json_load_file(path, 0, &error);
	if(abc_config_json == NULL){
		dcaf_log(DCAF_LOG_ERR,"load_am_ab_configuration: Failed to load am configuration: %s %s\n", path, error.text);
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if((abc_config = dcaf_new_am_abc_configuration()) == NULL){
		dcaf_log(DCAF_LOG_ERR,"load_am_ab_configuration: Failed to allocate memory\n");
		json_decref(abc_config_json);
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if((res = json_to_am_config(abc_config_json, &abc_config)) != DCAF_OK){
		json_decref(abc_config_json);
		dcaf_delete_am_abc_configuration(abc_config);
		return res;
	}
	return DCAF_OK;
}


/* This function is called when the default validator checks each certificate. In case the certificate is invalid
 *the protocol is aborted by setting the transaction state to  DCAF_STATE_UNAUTHORIZED and an error response for
 *C is saved in the sessions app data.
 *In case validation succeeds the fingerprint of the root certificate is extracted and saved in the sessions dcaf_contect.
 */
static int verify_cn_callback(const char *cn, const uint8_t *asn1_public_cert,
	size_t asn1_length, coap_session_t *session, unsigned depth,
	int validated, void *arg) {
	(void)asn1_length;

	dcaf_context_t *dcaf_ctx = (dcaf_context_t *)arg;
	if(!validated){
		dcaf_log(DCAF_LOG_INFO, "verify_cn_callback Peer is not authenticated. setting transaction state to unauthorized\n");
		coap_pdu_t *error_response = generate_pdu(session);
		(void) dcaf_set_error_response_msg(session, DCAF_ERROR_UNAUTHORIZED,
						error_response, (unsigned char *)"SAM not authorized");
		session->app = error_response;
		dcaf_ctx->transactions->state.act = DCAF_STATE_UNAUTHORIZED;
		return 0;
	}
	//Only safe fingerprint of root certificate
	if(! dcaf_ctx->root_ca_fp){
		char *fingerprint = get_fingerprint_from_cert(asn1_public_cert,
				asn1_length);
		dcaf_log(DCAF_LOG_INFO,
				"verify_cn_callback: Valid certificate with fingerprint %s and CN '%s' presented by client (%s)\n",
				fingerprint, cn, depth ? "CA" : "Certificate");
		dcaf_ctx->root_ca_fp = fingerprint;
	}
	return 1;
}


/*
 * Configures CAM with the root certificates in the certificate chain of the SAMs he trusts.
 * Additionally sets require_peer_cert and verify_peer_cert to 1.
 * The code is partly taken from the libcoap client example.
 */
static coap_dtls_pki_t *
setup_pki_cam(const char *root_ca_file, coap_context_t *ctx) {
	static coap_dtls_pki_t dtls_pki;
	static char client_sni[256];
	struct stat stbuf;
	dcaf_context_t *dcaf_ctx;

	dcaf_ctx = (dcaf_context_t *) coap_get_app_data(ctx);
	if(dcaf_ctx == NULL){
		dcaf_log(DCAF_LOG_ERR, "setup_pki_cam: Cannot access dcaf_contextf\n");
		return NULL;
	}

	if ((stat(root_ca_file, &stbuf) == 0) && S_ISDIR(stbuf.st_mode)) {
		dcaf_log(DCAF_LOG_ERR, "DIRECTORY\n");
		coap_context_set_pki_root_cas(ctx, NULL, root_ca_file);
	} else {
		coap_context_set_pki_root_cas(ctx, root_ca_file, NULL);

	}

	memset(&dtls_pki, 0, sizeof(dtls_pki));
	dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
	dtls_pki.verify_peer_cert = 1;
	dtls_pki.require_peer_cert = 1;
	dtls_pki.allow_self_signed = 0;
	dtls_pki.allow_expired_certs = 0;
	dtls_pki.cert_chain_validation = 1;
	dtls_pki.cert_chain_verify_depth = 1;
	dtls_pki.check_cert_revocation = 1;
	dtls_pki.allow_no_crl = 1;
	dtls_pki.allow_expired_crl = 1;
	dtls_pki.validate_cn_call_back = verify_cn_callback;
	dtls_pki.cn_call_back_arg = dcaf_ctx;
	dtls_pki.validate_sni_call_back = NULL;
	dtls_pki.sni_call_back_arg = NULL;
	memset(client_sni, 0, sizeof(client_sni));
	memcpy(client_sni, "localhost", 9);
	dtls_pki.client_sni = client_sni;
	dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM;
	return &dtls_pki;
}


/*
 * SAM is configured with his own key pair.
 * SAM does not receive or verify any peer certs, therefore require_peer_cert is set to 0.
 * The code is partly taken from the libcoap server example.
 */
static dcaf_result_t
setup_pki_sam(const char *cert_file, const char *key_file, coap_context_t *ctx) {
	coap_dtls_pki_t dtls_pki;
    if(!cert_file || !key_file){
    	dcaf_log(DCAF_LOG_ERR, "setup_pki_sam: Missing keys no pki generated.\n");
    	return DCAF_ERROR_INTERNAL_ERROR;
    }
    if(ctx == NULL){
	  dcaf_log(DCAF_LOG_WARNING, "setup_pki_sam: Missing context\n");
    }

	dtls_pki.verify_peer_cert = 1;
	dtls_pki.require_peer_cert = 0;
	dtls_pki.allow_self_signed = 1;
	dtls_pki.allow_expired_certs = 0;
	dtls_pki.cert_chain_validation = 1;
	dtls_pki.cert_chain_verify_depth = 3;
	dtls_pki.check_cert_revocation = 1;
	dtls_pki.allow_no_crl = 1;
	dtls_pki.allow_expired_crl = 1;
	dtls_pki.validate_cn_call_back = verify_cn_callback;
	dtls_pki.cn_call_back_arg = NULL;
	dtls_pki.validate_sni_call_back = NULL;
	dtls_pki.sni_call_back_arg = NULL;

	memset(&dtls_pki, 0, sizeof(dtls_pki));
	dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
	dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM;
	dtls_pki.pki_key.key.pem.public_cert = cert_file;
	dtls_pki.pki_key.key.pem.private_key = key_file;

	if(!coap_context_set_pki(ctx, &dtls_pki)){
		 dcaf_log(DCAF_LOG_ERR, "setup_pki_sam: Failed to setup pki\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	return DCAF_OK;
}

/*Frees the memory occupied by the AMs configuration*/
static void
cleanup_configuration(void){
	if(credential_descriptions != NULL){
		dcaf_delete_credential_list(credential_descriptions);
	}
	if(rules != NULL){
		dcaf_delete_rule_list(rules);
	}
	if(attribute_rules != NULL){
		dcaf_delete_attribute_rule_list(attribute_rules);
	}
	if(credential_store != NULL){
		dcaf_delete_credential_store(credential_store);
	}
	if(abc_config_json != NULL){
		json_decref(abc_config_json);
	}
	if(abc_config != NULL){
		dcaf_delete_am_abc_configuration(abc_config);
	}
}

/*Frees the main context.
 */
static void
cleanup_context(dcaf_context_t *ctx){
	//these might only be set by SAM
	if(ctx->session_nonce != NULL)
		dcaf_free_type(DCAF_NONCE, ctx->session_nonce);
	if(ctx->treq != NULL)
		dcaf_delete_ticket_request(ctx->treq);
	if (ctx != NULL)
		dcaf_free_context (ctx);
}

/* Frees the memory occupied by CAM during a session with another SAM.
 */
static void
cleanup_session(dcaf_context_t *ctx, coap_session_t *session){
	if (session != NULL){
		if(session->app != NULL){
			coap_delete_pdu((coap_pdu_t *) session->app);
		}
		coap_session_release(session);
	}
	//this might only set by CAM in a session with SAM
	if (ctx->root_ca_fp != NULL)
		dcaf_free_type(DCAF_VAR_STRING, ctx->root_ca_fp);
	if (ctx != NULL)
		dcaf_free_context(ctx);
	coap_cleanup();
}


/* Checks if required values are present in the am configuration. If values
 only required for CAM are not set type is set to DCAF_SAM, if values only required for
 SAM are not set type is set to DCAF_CAM. Otherwise type is set to DCAF_BOTH.
 Returns the DCAF_ERROR_INTERNAL_ERROR if values required for both AMs are not set,
 DCAF_OK otherwise.
 */
static dcaf_result_t check_abc_config(){
	dcaf_result_t res = DCAF_ERROR_INTERNAL_ERROR;
	//Some values are always required
	if(empty_string(abc_config->issuer_path) || empty_string(abc_config->abc_binary_path)
			 || empty_string(abc_config->abc_fifo_path)){
		dcaf_log(DCAF_LOG_ERR, "check_abc_config: Invalid configuration\n");
		return res;
	}
	//some values required for CAM
	if(!empty_string(abc_config->attribute_rule_path) && !empty_string(abc_config->trusted_certificates_path)  &&
			!empty_string(abc_config->credential_path)){
		type = DCAF_CAM;
		res = DCAF_OK;
	}
	//some values required for SAM
	if(!empty_string(abc_config->rule_path) && !empty_string(abc_config->certificate_path)  &&
		!empty_string(abc_config->private_key_path)){
		if(type == DCAF_UNKNOWN_AM)
			type = DCAF_SAM;
		else
			type = DCAF_BOTH;
		res = DCAF_OK;

	}
	if(type == DCAF_UNKNOWN_AM){
		dcaf_log(DCAF_LOG_ERR, "check_abc_config: Invalid configuration\n");
		res =  DCAF_ERROR_INTERNAL_ERROR;
	}
	return res;
}

/* Initializes the am Configuration. Returns DCAF_OK on success and
 * DCAF_ERROR_INTERNAL_ERROR otherwise.
 * On success the method allocates memory that has to be freed
 * using cleanup configuration.
 */
static dcaf_result_t
init_configuration(char *config_path, coap_context_t *ctx){
	dcaf_log(DCAF_LOG_INFO, "init: Initializing ABC configuration...\n");
	dcaf_result_t res;
	if((res = load_am_ab_configuration(config_path)) != DCAF_OK)
		return res;
	if((res = check_abc_config()) != DCAF_OK)
		goto delete_conf;

	if(res != init_abc_configuration(abc_config->abc_binary_path, abc_config->abc_fifo_path)){
		goto delete_conf;
	}

	dcaf_log(DCAF_LOG_INFO, "init: Loading credential descriptions...\n");
	if((res = traverse_issuer_directory(abc_config->issuer_path, &credential_descriptions)) != DCAF_OK)
		return res;

	if (type == DCAF_SAM || type == DCAF_BOTH) {
		dcaf_log(DCAF_LOG_INFO, "init: Loading rule list...\n");
		if ((res = load_rule_list(abc_config->rule_path)) != DCAF_OK)
			goto delete_descr;
		dcaf_log(DCAF_LOG_INFO, "init: Setup pki with certfile: %s\n",
				abc_config->certificate_path);
		if ((res = setup_pki_sam(abc_config->certificate_path,
				abc_config->private_key_path, ctx)) != DCAF_OK){
			dcaf_delete_rule_list(rules);
			goto delete_descr;
		}
	}
	if (type == DCAF_CAM || type == DCAF_BOTH) {
		dcaf_log(DCAF_LOG_INFO, "init: Loading attribute rule list...\n");
		if ((res = load_attribute_rule_list(abc_config->attribute_rule_path))
				!= DCAF_OK)
			goto delete_descr;
		dcaf_log(DCAF_LOG_INFO, "init: Fill credential store...\n");
		if ((res = traverse_credential_directory(abc_config->credential_path,
				&credential_store)) != DCAF_OK){
			dcaf_delete_attribute_rule_list(attribute_rules);
			goto delete_descr;
		}
	}
	return DCAF_OK;

	delete_descr:
	dcaf_delete_credential_list(credential_descriptions);
	delete_conf:
	dcaf_delete_am_abc_configuration(abc_config);
	json_decref(abc_config_json);
	return res;
}

/*
 * On receiving an access request the AM first checks if it is capable to act as SAM, the request payload is valid and the SAM URI can be resolved.
 *If so it sets up a PKI and starts a new TLS session with SAM, creates the ticket request and sends it. The session is ended when the
 *state of the newly created transaction is set to  DCAF_STATE_TICKET_GRANT or DCAF_STATE_UNAUTHORIZED. The AM now checks whether a response for the client has been
 *created (and is contained in the session) and if so forwards it. Otherwise it creates a new error response and sends it to the client. Possible
 *response send back to the client are:
 ** An error response with code bad request (4.00) if the am is not capable to act as SAM or if the request cannot be pardes.
 ** An error response wit code internal server error (5.00) if any kind of error occurs
 **  An error response with code unauthorized (4.01) and the additional message "SAM not authorized" if the certificate presented by SAM
 **  during the handshake can not be verified
 ** Any response returned by @hnd_attribute_info and @hnd_ticket response in a later state of the protocol
 */
static void hnd_post_access_request(coap_context_t *ctx,
		struct coap_resource_t *resource, coap_session_t *session,
		coap_pdu_t *request, coap_binary_t *token, coap_string_t *query,
		coap_pdu_t *response) {
	(void)ctx;
	(void)resource;
	(void)token;
	(void)query;
	//new session
	dcaf_context_t *dcaf_sam;
	coap_pdu_t *new_request = NULL;
	coap_context_t *ctx_sam;
	coap_session_t *session_sam = NULL;
	dcaf_ticket_request_t *treq = NULL;
	dcaf_result_t res;
	dcaf_transaction_t *t = NULL;
	coap_address_t dst;


	dcaf_log(DCAF_LOG_INFO, "Entering hnd_post_access_request\n");

	if(type == DCAF_SAM){
		dcaf_log(DCAF_LOG_ERR,
				"hnd_post_access_request: Rejecting access request because I'm SAM\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_BAD_REQUEST,
				response);
		return;
	}
	//parse the initial access request (ticket request) from the client
	if ((res = dcaf_parse_ticket_request(request, &treq)) != DCAF_OK ) {
		dcaf_log(DCAF_LOG_ERR, "hnd_post_access_request: Cannot parse ticket request\n");
		(void) dcaf_set_error_response(session, res, response);
		return;
	}
	//resolve SAM address
	if (resolve_address(treq->aud, &dst) != DCAF_OK) {
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				response);
		dcaf_delete_ticket_request(treq);
		return;
	}


//	///////////////////////////////////////////////Start new session with SAM//////////////////////////////////
	dcaf_sam = dcaf_new_context(&config);
	if (!dcaf_sam || !(ctx_sam = dcaf_get_coap_context(dcaf_sam))) {
		dcaf_log(DCAF_LOG_ERR, "hnd_post_access_request: failed to generate context\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				response);
		goto cleanup;
	}


	init_resources(ctx_sam);
	coap_register_response_handler(ctx_sam, hnd_attribute_info);

	coap_dtls_pki_t *tls_pki;
	if(!(tls_pki = setup_pki_cam(abc_config->trusted_certificates_path,ctx_sam))){
		dcaf_log(DCAF_LOG_ERR, "hnd_post_access_request: Cannot setup PKI. No TLS connection possible..\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				response);
		goto cleanup;
	}

	session_sam = coap_new_client_session_pki(ctx_sam, nullptr, &dst, COAP_PROTO_TLS, tls_pki);
	if (! session_sam ) {
		dcaf_log(DCAF_LOG_EMERG, "hnd_post_access_request: Cannot create client session\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				response);
		goto cleanup;
	}

	if(! (new_request = generate_pdu(session_sam))){
		dcaf_log(DCAF_LOG_EMERG,
				"hnd_post_access_request: Cannot create pdu\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				response);
		goto cleanup;

	}
	if(dcaf_set_ticket_request(new_request, &treq) != DCAF_OK){
		dcaf_log(DCAF_LOG_EMERG,
				"hnd_post_access_request: Cannot create ticket request\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				response);
		goto cleanup;
	}

	t = dcaf_create_transaction(dcaf_sam, session_sam, new_request);
	if (!t) {
		dcaf_log(DCAF_LOG_WARNING,
				"hnd_post_access_request: cannot create new transaction\n");
		goto cleanup;
	}

	dcaf_log(DCAF_LOG_INFO, "hnd_post_access_request: sending CoAP request!\n");
	coap_show_pdu(LOG_INFO, new_request);

	coap_send(session_sam, new_request);
	run_and_wait(ctx_sam, session_sam, 10);

	////////////////////////////////////////
	///////after this returned ticket should be in session
	dcaf_log(DCAF_LOG_INFO,
			"hnd_post_access_request: Sending back to client\n");

	if (session_sam->app != NULL) {
		copy_pdu(response, (coap_pdu_t *) session_sam->app);
	} else {
		dcaf_log(DCAF_LOG_ERR, "hnd_post_access_request: Cannot set ticket grant\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				response);
	}

	dcaf_log(DCAF_LOG_INFO, "response is\n");
	coap_show_pdu(LOG_INFO, response);

	cleanup:
		dcaf_log(DCAF_LOG_INFO, "Session finished now cleanup\n");
		if(treq != NULL)
			dcaf_delete_ticket_request(treq);
		if(t != NULL)
			dcaf_delete_transaction(dcaf_sam,t);
		cleanup_session(dcaf_sam, session_sam);
}

/* On receiving a ticket request the AM first checks whether the request is received on a secure channel and whether it can be parsed
 *properly. If so it determines the required credential and attribute values to obtain the requested permissions according to its ruleset.
 *It further generates a fresh random nonce and constructs the attribute info message. The ticket request such as the nonce
 *are saved to the sessions dcaf_context to make them accessible in a later state of the protocol.
 * Response send back to CAM can be:
 ** An error response with code unauthorized (4.01) if the request was not received on a secure channel
 ** An error response with code bad request (4.00) if the request cannot be parsed properly
 ** An error response with code internal server error (5.00) if some error occurred
 ** An error response with code not implemented (5.01) if no valid requirements are configured in the ruleset (invalid requirements would be
 *unsupported attributes or attributes from different credentials)
 ** An attribute info message with response code changed (2.04) containing the nonce the id of the needed credential and a
 * binary flag indicating the indices of the attributes whose values have to be disclosed
 */
static void hnd_post_token_request(coap_context_t *ctx,
		struct coap_resource_t *resource, coap_session_t *session,
		coap_pdu_t *request, coap_binary_t *token, coap_string_t *query,
		coap_pdu_t *response) {
	(void) ctx;
	(void) resource;
	(void) token;
	(void) query;
	dcaf_ticket_request_t *treq = NULL;
	dcaf_nonce_t *n = NULL;
	dcaf_result_t res;
	dcaf_context_t *dcaf_ctx;
	uint64_t cred_id;
	uint attribute_flag;
	int nonce_len;

	dcaf_log(DCAF_LOG_INFO, "Entering hnd_post_token_request\n");

	/*
	 * Check if the request was received on a secure channel.
	 */
  if(! is_secure(session)){
	  dcaf_log(DCAF_LOG_ERR, "hnd_post_token_reques: Authorization via an insecure channel is not supported!\n");
	  (void)dcaf_set_error_response(session, DCAF_ERROR_UNAUTHORIZED, response);
	  return;
  }
	res = dcaf_parse_ticket_request(request, &treq);
	if (res != DCAF_OK) {
		(void) dcaf_set_error_response(session, res, response);
		return;
	}
	if((res = find_required_attributes(rules, treq->aif, &cred_id, &attribute_flag)) != DCAF_OK){
	(void) dcaf_set_error_response(session, res,
				response);
		goto abort_protocol;
	}
	//save ticket request to session
	dcaf_ctx = (dcaf_context_t *) coap_get_app_data(session->context);
	if(dcaf_ctx == NULL){
		dcaf_log(DCAF_LOG_ERR, "hnd_post_token_request: Cannot load dcaf_context from session\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
							response);
		goto abort_protocol;
	}
	dcaf_ctx->treq = treq;

	//determine required nonce length
	if((nonce_len = get_required_nonce_length_by_credential(credential_descriptions, cred_id)) == 0){
		dcaf_log(DCAF_LOG_ERR,
				"hnd_post_token_request: Cannot determine required nonce length\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				response);
		goto abort_protocol;
	}
	//generate a fresh random nonce and save it to session
	n = dcaf_new_nonce(nonce_len);
	if (n == NULL) {
		dcaf_log(DCAF_LOG_ERR,
				"hnd_post_token_request: Nonce generation failed\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				response);
		goto abort_protocol;
	}
	dcaf_prng(n->nonce, n->nonce_length);
	if(n->nonce_length == 0){
		dcaf_log(DCAF_LOG_ERR, "hnd_post_token_request: Nonce generation failed\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
											response);
		goto abort_protocol;
	}
	dcaf_ctx->session_nonce = n;
	dcaf_log(DCAF_LOG_DEBUG, "hnd_post_token_request: Generating attribute info for credential %" PRIu64 " with attributes %i\n", cred_id, attribute_flag);

	if(dcaf_set_attribute_info(response, cred_id, attribute_flag, n) == DCAF_OK)
		return;//if everything went well we don't want to cleanup

	abort_protocol:
	dcaf_log(DCAF_LOG_INFO, "Aborting protocol due to error\n");
	if(treq != NULL){
		dcaf_delete_ticket_request(treq);
	}
	if(n != NULL){
		dcaf_free_type(DCAF_NONCE, n);
	}
}


/*When CAM receives the response to a Ticket Request message on a secure channel it first checks weather he received
 * a valid Attribute Info message by checking the response code (in case he received an error message) and
 * by trying to parse it. On success the attribute rule list is searched for the permissions corresponding to
 * the fingerprint of the certificate that SAMs certificate has been signed with (saved in the sessions dcaf_context
 * during the verify callback). Subsequently CAM checks whether SAM is eligible to receive a selective disclosure
 * of the requested attributes. On success the respective credential path and corresponding issuers public is determined
 * and the selective disclosure is generated and send to SAM in a Dislosure Proof message.
 *If any error occurs during computations an error response has been received initially
 *the protocol is aborted by setting the transaction state to  DCAF_STATE_UNAUTHORIZ and an error response for C is saved in the sessions app data.
 *Error responses might be:
 ** Any error response received from SAM
 ** An error response with code unauthorized (4.01) if CAM is not in possession of the credential requested by SAM
 ** An error response with code unauthorized (4.01) and the additional message "SAM not authorized" if SAM is not eligible to receive a
 * selective disclosure on the requested attribute values.
 ** An error response with code internal server error (5.00) if the message is received via an insecure channel or any error
 * occurs during computations.
 */
static void hnd_attribute_info(coap_context_t *ctx, coap_session_t *session,
		coap_pdu_t *sent, coap_pdu_t *received, const coap_tid_t id) {
	(void) sent;
	(void) id;
	dcaf_context_t *dcaf_ctx;
	//the new request  to SAM containing the attribute proof - this is only sent if proof generation succeeds
	coap_pdu_t *new_request = NULL;
	//if proof generation fails an error response is returned to C instead
	coap_pdu_t *error_response;
	dcaf_attribute_request_t *areq = NULL;
	dcaf_result_t res;
	issuer_st *iss = NULL;
	char *cred_path = NULL;
	attribute_permission_list_st *granted_permissions = NULL;
	char *fingerprint = NULL;

	dcaf_log(DCAF_LOG_INFO, "Entering hnd_attribute info\n");

	/*
	 * Check if the request was received on a secure channel.
	 */
	if (!is_secure(session)) {
		dcaf_log(DCAF_LOG_ERR,
				"hnd_attribute info: received response via insecure channel!\n");
		error_response = generate_pdu(session);
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				error_response);
		goto abort_protocol;
	}
	if (received->code != COAP_RESPONSE_CODE(204)) {
		dcaf_log(DCAF_LOG_ERR,
				"hnd_attribute info: received error response!\n");
		session->app = coap_new_pdu(session);
		copy_pdu((coap_pdu_t *)session->app, received);
		set_transaction_state(session, DCAF_STATE_UNAUTHORIZED);
		return;
	}
	res = dcaf_parse_attribute_info(received, &areq, credential_descriptions);
		if (res != DCAF_OK) {
			dcaf_log(DCAF_LOG_ERR,
					"hnd_attribute info: Cannot parse attribute info\n");
			error_response = generate_pdu(session);
			(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
					error_response);
			goto abort_protocol;
		}

	//Get server root certificate from dcaf_context
	dcaf_ctx = (dcaf_context_t *) coap_get_app_data(session->context);
	fingerprint = dcaf_ctx->root_ca_fp;
	granted_permissions =
			find_attribute_permssions_in_rule_list(attribute_rules,
					fingerprint);
	if (granted_permissions == NULL) {
		dcaf_log(DCAF_LOG_ERR,
				"hnd_attribute info: No permissions configured for root certificate %s\n",
				fingerprint);
		error_response = generate_pdu(session);
		(void) dcaf_set_error_response_msg(session, DCAF_ERROR_UNAUTHORIZED,
				error_response, (unsigned char *)"SAM not authorized");
		goto abort_protocol;
	}

	dcaf_log(DCAF_LOG_INFO,
			"Check permissions for root certificate %s to get attributes %i from credential %" PRIu64 "\n",
			fingerprint, areq->atributes, areq->cred_id);

	//Compare requested attributes with attributes that peer is allowed to request
	res = search_attribute_permsissions(granted_permissions, areq->cred_id,
			areq->atributes);
	if (res != DCAF_OK) {
		dcaf_log(DCAF_LOG_ERR,
				"hnd_attribute info: Cannot grant authorization to access requested attributes\n");
		error_response = generate_pdu(session);
		(void) dcaf_set_error_response_msg(session, res, error_response, (unsigned char *)"SAM not authorized");
		goto abort_protocol;
	}

	dcaf_log(DCAF_LOG_DEBUG,
			"hnd_attribute info: Preparing selective disclosure on credential with id %" PRIu64 "\n",
			areq->cred_id);
	/*
	 * Find credential and issuer public key matching credential_id
	 */
	iss = find_issuer_by_credential_id(credential_descriptions,
			areq->cred_id);
	if (iss == NULL || iss->id == 0 || iss->public_key == NULL) {
		dcaf_log(DCAF_LOG_ERR,
				"hnd_attribute info: No issuer configured for the requested credential id\n");
		error_response = generate_pdu(session);
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				error_response);
		goto abort_protocol;
	}

	cred_path = find_credential_path_by_id(credential_store,
			areq->cred_id);
	if (cred_path == NULL) {
		dcaf_log(DCAF_LOG_ERR,
				"hnd_attribute info: No credential for the requested credential id\n");
		error_response = generate_pdu(session);
		(void) dcaf_set_error_response(session, DCAF_ERROR_UNAUTHORIZED,
				error_response);
		goto abort_protocol;
	}

	//register a response handler
	coap_register_response_handler(ctx, hnd_ticket_response);

	/*
	 * Creat a new request containing the original ticket request and an attribute proof
	 */
	if((new_request = generate_pdu(session)) == NULL){
		dcaf_log(DCAF_LOG_ERR,
						"hnd_attribute info: Cannot generated pdu\n");
		error_response = generate_pdu(session);
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				error_response);
		goto abort_protocol;

	}

	if((res = dcaf_set_disclosure_proof(areq, new_request, cred_path, iss->public_key))!= DCAF_OK)
	{
		dcaf_log(DCAF_LOG_ERR,
						"hnd_attribute info: Cannot generated attribute proof\n");
		error_response = generate_pdu(session);
		(void) dcaf_set_error_response(session, res,
				error_response);
		goto abort_protocol;

	}
	coap_send(session, new_request);
	if(areq != NULL)
		dcaf_delete_attribute_request(areq);
	return;	//everything went well and we do not want to abort the protocol

	abort_protocol:
	dcaf_log(DCAF_LOG_INFO, "Aborting protocol due to error\n");
	if(areq != NULL)
		dcaf_delete_attribute_request(areq);
	session->app = error_response;
	set_transaction_state(session, DCAF_STATE_UNAUTHORIZED);
}

/* When the Disclosure Proof message is received on a secure channel and on success the disclosed attributes are compared to the
 *attribute conditions configured for the permissions requested by the initial Ticket Request (and saved to the sessions dcaf_context).
 *If the attribute indices and values match the proof is verified using the respective issuers public key and the nonce initially
 *send to CAM.
 *On success an access ticket is created and send back to CAM in a Ticket Grant message.
 *Possible responses to CAM are:
 ** An error message with code unauthorized (4.01) if the request is received on an insecure channel, if the disclosed attribute
 *values do not match the required or if the disclosure proof is not valid
 ** An error message with code bad request (4.00) if the request cannot be parsed properly
 ** An error message with code internal server error (5.00) if any error occurs
 ** An error message with code not implemented (5.01) if no valid requirements are configured in the ruleset for the permissions
 * requested in the initial Ticket Request (invalid requirements would be unsupported attributes or attributes from different credentials)
*/
static void hnd_post_disclosure_proof(coap_context_t *ctx,
		struct coap_resource_t *resource, coap_session_t *session,
		coap_pdu_t *request, coap_binary_t *token, coap_string_t *query,
		coap_pdu_t *response) {
	(void) ctx;
	(void) resource;
	(void) token;
	(void) query;
	dcaf_result_t res;
	dcaf_context_t *dcaf_ctx;
	dcaf_ticket_request_t *treq = NULL;
	str_st *proofstring = NULL;
	attribute_list_st *disclose_attributes = NULL;
	uint64_t cred_id;
	issuer_st *iss = NULL;

	dcaf_log(DCAF_LOG_INFO, "Entering hnd_post_attribute_proof\n");

	/*
	 * Check if the request was received on a secure channel.
	 */
  if(! is_secure(session)){
	  dcaf_log(DCAF_LOG_ERR, "hnd_post_attribute_proof: Authorization via an insecure channel is not supported!\n");
	  (void)dcaf_set_error_response(session, DCAF_ERROR_UNAUTHORIZED, response);
	  return;
  }
	if ((res = dcaf_parse_disclosure_proof(request, &proofstring)) != DCAF_OK) {
		dcaf_delete_str(proofstring);
		dcaf_log(DCAF_LOG_ERR, "hnd_post_attribute_proof: Cannot parse attribute proof\n");
		(void) dcaf_set_error_response(session, res, response);
		return;
	}


	if ((res = get_disclosed_attributes_from_proof(proofstring, &disclose_attributes)) != DCAF_OK) {
		dcaf_log(DCAF_LOG_ERR, "hnd_post_attribute_proof: Cannot parse disclosed attributes");
		(void) dcaf_set_error_response(session, res,
				response);
		goto finish;
	}

	dcaf_ctx = (dcaf_context_t *) coap_get_app_data(session->context);
	if(dcaf_ctx == NULL){
		dcaf_log(DCAF_LOG_ERR, "hnd_post_attribute_proof: Cannot access dcaf_contextf\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR, response);
		goto finish;
	}
	treq = dcaf_ctx->treq;
	if(treq == NULL){
		dcaf_log(DCAF_LOG_ERR, "hnd_post_attribute_proof: Cannot get ticket request from context\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR, response);
		goto finish;
	}

	if ((res = check_attribute_conditions(rules, treq->aif, disclose_attributes, &cred_id)) != DCAF_OK){
		(void) dcaf_set_error_response(session, res,
				response);
		goto finish;
	}

	iss = find_issuer_by_credential_id(credential_descriptions, cred_id);
	if(iss == NULL){
		dcaf_log(DCAF_LOG_ERR, "hnd_post_attribute_proof: No issuer configured for credential id\n");
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				response);
		goto finish;
	}

	if ((res = verify_proof(iss->public_key, dcaf_ctx->session_nonce, proofstring)) != DCAF_OK) {
		dcaf_log(DCAF_LOG_ERR, "hnd_post_attribute_proof: attribute proof did not verify\n");
		(void) dcaf_set_error_response(session, res, response);
		goto finish;
	}

	dcaf_set_ticket_grant(session, treq, response);

	finish:
		if(proofstring != NULL)
			dcaf_delete_str(proofstring);
		if(disclose_attributes != NULL)
			dcaf_delete_attribute_list(disclose_attributes);
}


/* When the response to a Disclosure Proof message is received on a secure channel it is saved in the sessions app data to be forwarded to
 *C once the session is terminated. The transaction state is set depending on the response code either to DCAF_STATE_UNAUTHORIZED or to
 *DCAF_STATE_TICKET_GRANT. The response saved in the sessions app data can be one of the following:
 ** An error response with code internal server error (5.00) if the response was received on an insecure channel
 ** Any error response received from SAM
 ** A Ticket Grant message received from CAM with code ok (2.05)
 */
static void hnd_ticket_response(coap_context_t *ctx,
		coap_session_t *session,
		coap_pdu_t *sent, coap_pdu_t *received, const coap_tid_t id) {

	dcaf_log(DCAF_LOG_INFO, "Entering hnd_ticket_response\n");
	(void) ctx;
	(void) session;
	(void) sent;
	(void) id;
	coap_pdu_t *error_response;
	/*
	 * Check if the request was received on a secure channel.
	 */
	if (!is_secure(session)) {
		dcaf_log(DCAF_LOG_ERR,
				"hnd_ticket_response: Received response via insecure channel!\n");
		error_response = generate_pdu(session);
		(void) dcaf_set_error_response(session, DCAF_ERROR_INTERNAL_ERROR,
				error_response);
		session->app = error_response;
		set_transaction_state(session, DCAF_STATE_UNAUTHORIZED);
		return;
	}

	session->app = coap_new_pdu(session);
	copy_pdu((coap_pdu_t *)session->app, received);
	if(received->code != COAP_RESPONSE_CODE(200))
		set_transaction_state(session, DCAF_STATE_UNAUTHORIZED);
	else
		set_transaction_state(session, DCAF_STATE_TICKET_GRANT);
}


/* Handler for unknown resource path. Returns 404.
 */
static void
hnd_unknown(coap_context_t *ctx,
            struct coap_resource_t *resource,
            coap_session_t *session,
            coap_pdu_t *request,
            coap_binary_t *token,
            coap_string_t *query,
            coap_pdu_t *response) {
  (void)ctx;
  (void)resource;
  (void)session;
  (void)token;
  (void)query;
  (void)request;
  dcaf_log(DCAF_LOG_DEBUG, "Entering hnd_unknown\n");

  /* the default response code */
  response->code = COAP_RESPONSE_CODE(404);

}

/*
 * Registers the handlers for the default resources.
 * The code is partly taken from the dcaf_am example.
 */
static void
init_resources(coap_context_t *coap_context) {
  const char mediatypes[] = DCAF_MEDIATYPE_DCAF_CBOR_STRING " " DCAF_MEDIATYPE_ACE_CBOR_STRING;

  default_resource = coap_resource_init(coap_make_str_const(DCAF_AM_DEFAULT_PATH), 0);
  coap_register_handler(default_resource, COAP_REQUEST_POST, hnd_post_access_request);

  ticket_resource = coap_resource_init(coap_make_str_const(DCAF_AM_TREQ_PATH), 0);
  coap_register_handler(ticket_resource, COAP_REQUEST_POST, hnd_post_token_request);


  proof_resource = coap_resource_init(coap_make_str_const(DCAF_AM_ARES_PATH), 0);
  coap_register_handler(proof_resource, COAP_REQUEST_POST, hnd_post_disclosure_proof);


  /* add values for supported content-formats */
  coap_add_attr(default_resource, coap_make_str_const("ct"),
                coap_make_str_const(mediatypes), 0);
  coap_add_resource(coap_context, default_resource);

  coap_add_attr(ticket_resource, coap_make_str_const("ct"),
                  coap_make_str_const(mediatypes), 0);
  coap_add_resource(coap_context, ticket_resource);


  coap_add_attr(proof_resource, coap_make_str_const("ct"),
                  coap_make_str_const(mediatypes), 0);
  coap_add_resource(coap_context, proof_resource);


  default_resource = coap_resource_unknown_init(hnd_unknown);
  if (default_resource) {
    coap_register_handler(default_resource, COAP_REQUEST_POST, hnd_unknown);
    coap_add_resource(coap_context, default_resource);
  }
}


/*
 *Starts AM listening for requests.
 * The code is partly taken from the dcaf_am example.
 */
int
main(int argc, char **argv) {
  dcaf_context_t  *dcaf;
  coap_context_t  *ctx;
  std::string addr_str = "::1";
  int opt;
  coap_log_t log_level = LOG_ERR;
  struct sigaction sa;
  char *abc_config_path = NULL;

  unsigned int wait_ms = 0;

  memset(&config, 0, sizeof(config));
  config.host = addr_str.c_str();
  config.coap_port = DCAF_DEFAULT_COAP_PORT;
  config.coaps_port = DCAF_DEFAULT_COAPS_PORT;

  while ((opt = getopt(argc, argv, "A:p:v:c:t")) != -1) {
    switch (opt) {
    case 'A':
      config.host = optarg;
      break;
    case 'c' :
      abc_config_path = optarg;
      break;
    case 'p' :
      config.coap_port = static_cast<uint16_t>(strtol(optarg, nullptr, 10));
      config.coaps_port = config.coap_port + 1;
      break;
    case 'v' :
      log_level = static_cast<coap_log_t>(strtol(optarg, nullptr, 10));
      break;
    default:
      usage(argv[0]);
      exit(1);
    }
  }
  if(abc_config_path == NULL){
	  usage(argv[0]);
	  exit(1);
  }
  dcaf_log(DCAF_LOG_INFO, "Coap port: %i\n", config.coap_port);
  dcaf_log(DCAF_LOG_INFO, "Coaps port: %i\n", config.coaps_port);


  coap_startup();
  coap_dtls_set_log_level(log_level);
  coap_set_log_level(log_level);
  dcaf_set_log_level((dcaf_log_t)log_level);

  /* set random number generator function for DCAF library */
  dcaf_set_prng(rnd);

  dcaf = dcaf_new_context(&config);
  if (!dcaf || !(ctx = dcaf_get_coap_context(dcaf)))
    return -1;

  if(init_configuration(abc_config_path, ctx) != DCAF_OK){
	  dcaf_log(DCAF_LOG_ERR, "Failed to initalize AM configuration\n");
	  cleanup_context(dcaf);
	  coap_cleanup();
	  exit(1);
    }
  dcaf_log(DCAF_LOG_INFO, "AM configuration initialized\n");
  init_resources(ctx);

  memset (&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = handle_sigint;
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

  while (!quit) {
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
  dcaf_log(DCAF_LOG_INFO, "Loop terminated now cleanup\n");
  cleanup_configuration();
  cleanup_context(dcaf);
  coap_cleanup();
  return 0;
}
