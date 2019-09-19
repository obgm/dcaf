/*
 * am_util.cc -- utility fuctions for DCAF authorization managers
 *
 * Copyright (C) 2018-2019 Sara Stadler
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 *
 * Parts of the code are taken from the libcoap client and server examples.
 * Parts of the code are taken from the dcaf am example.
 */
#include "am_util.hh"

unsigned int wait_ms = 0;
int wait_ms_reset = 0;
int obs_started = 0;
unsigned int obs_seconds = 30; /* default observe time */
unsigned int obs_ms = 0; /* timeout for current subscription */
int obs_ms_reset = 0;

unsigned char msgtype = COAP_MESSAGE_CON; /* usually, requests are sent confirmable */
static unsigned char _token_data[8];
coap_binary_t the_token = { 0, _token_data };
int flags = 0;
static coap_optlist_t *optlist = NULL;
coap_block_t block = { 0, 0, 6 };

#define FLAGS_BLOCK 0x01


/*
 This function is taken (and slightly modified) from the libcoap client example.
 */
static coap_tid_t clear_obs(coap_context_t *ctx, coap_session_t *session) {
	coap_pdu_t *pdu;
	coap_optlist_t *option;
	coap_tid_t tid = COAP_INVALID_TID;
	unsigned char buf[2];
	(void) ctx;

	/* create bare PDU w/o any option  */
	pdu = coap_pdu_init(msgtype, COAP_REQUEST_GET, coap_new_message_id(session),
			coap_session_max_pdu_size(session));

	if (!pdu) {
		return tid;
	}

	if (!coap_add_token(pdu, the_token.length, the_token.s)) {
		coap_log(LOG_CRIT, "clear_obs: cannot add token\n");
		goto error;
	}

	for (option = optlist; option; option = option->next) {
		if (option->number == COAP_OPTION_URI_HOST) {
			if (!coap_add_option(pdu, option->number, option->length,
					option->data)) {
				goto error;
			}
			break;
		}
	}

	if (!coap_add_option(pdu, COAP_OPTION_OBSERVE,
			coap_encode_var_safe(buf, sizeof(buf), COAP_OBSERVE_CANCEL), buf)) {
		coap_log(LOG_CRIT, "clear_obs: cannot add option Observe: %u\n",
				COAP_OBSERVE_CANCEL);
		goto error;
	}

	for (option = optlist; option; option = option->next) {
		switch (option->number) {
		case COAP_OPTION_URI_PORT:
		case COAP_OPTION_URI_PATH:
		case COAP_OPTION_URI_QUERY:
			if (!coap_add_option(pdu, option->number, option->length,
					option->data)) {
				goto error;
			}
			break;
		default:
			;
		}
	}

	if (flags & FLAGS_BLOCK) {
		block.num = 0;
		block.m = 0;
		coap_add_option(pdu, COAP_OPTION_BLOCK2,
				coap_encode_var_safe(buf, sizeof(buf),
						(block.num << 4 | block.m << 3 | block.szx)), buf);
	}

	if (coap_get_log_level() < LOG_DEBUG)
		coap_show_pdu(LOG_INFO, pdu);

	tid = coap_send(session, pdu);

	if (tid == COAP_INVALID_TID)
		coap_log(LOG_DEBUG, "clear_obs: error sending new request\n");

	return tid;
	error:

	coap_delete_pdu(pdu);
	return tid;
}


int run_and_wait(coap_context_t *ctx, coap_session_t *session,
		int wait_seconds) {
	int result = EXIT_FAILURE;

	wait_ms = wait_seconds * 1000;
	int ready = 0;
	while (!(ready && coap_can_exit(ctx))) {
		result = coap_run_once(ctx,
				wait_ms == 0 ? obs_ms :
				obs_ms == 0 ? min(wait_ms, 1000) : min(wait_ms, obs_ms));

		if (result >= 0) {
			if (wait_ms > 0 && !wait_ms_reset) {
				if ((unsigned) result >= wait_ms) {
					coap_log(LOG_INFO, "run_and_wait: timeout\n");
					break;
				} else {
					wait_ms -= result;
				}
			}
			if (obs_ms > 0 && !obs_ms_reset) {
				if ((unsigned) result >= obs_ms) {
					coap_log(LOG_DEBUG,
							"run_and_wait: clear observation relationship\n");
					if (session != NULL) {
						clear_obs(ctx, session); /* FIXME: handle error case COAP_TID_INVALID */
					}
					/* make sure that the obs timer does not fire again */
					obs_ms = 0;
					obs_seconds = 0;
				} else {
					obs_ms -= result;
				}
			}
			wait_ms_reset = 0;
			obs_ms_reset = 0;
		}
		if(get_transaction_state(session) == DCAF_STATE_TICKET_GRANT || get_transaction_state(session) == DCAF_STATE_UNAUTHORIZED){
			dcaf_log(DCAF_LOG_INFO, "run_and_wait: transaction finished\n");
			ready = 1;
		}
	}
	return result;
}


am_abc_configuration_st*
dcaf_new_am_abc_configuration(void) {
	am_abc_configuration_st* a = (am_abc_configuration_st*)malloc(sizeof(am_abc_configuration_st));
	return a;
}

void
dcaf_delete_am_abc_configuration(am_abc_configuration_st* a) {
	free(a);
}

coap_pdu_t *generate_pdu(coap_session_t *session) {
	coap_pdu_t *pdu;
	uint8_t token[DCAF_DEFAULT_TOKEN_SIZE];
	pdu = coap_new_pdu(session);
	if (!pdu) {
		coap_log(LOG_WARNING, "generate_pdu: cannot create new PDU\n");
		return NULL;
	}

	/* generate random token */
	if (!dcaf_prng(token, sizeof(token))
			|| !coap_add_token(pdu, sizeof(token), token)) {
		coap_log(LOG_DEBUG, "cannot add token to pdu\n");
		return NULL;
	}

	//TCP is always reliable
	pdu->type = COAP_MESSAGE_NON;
	pdu->tid = coap_new_message_id(session);
	return pdu;
}


void
rnd(uint8_t *out, size_t len) {
  static std::random_device rd;
  static std::seed_seq seed{rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()};
  static std::mt19937 generate(seed);
  using rand_t = uint16_t;
  static std::uniform_int_distribution<rand_t> rand;

  for (; len; len -= sizeof(rand_t), out += sizeof(rand_t)) {
    rand_t v = rand(generate);
    memcpy(out, &v, min(len, sizeof(rand_t)));
  }
}

dcaf_transaction_state_t get_transaction_state(coap_session_t *session){
	dcaf_context_t *dcaf = (dcaf_context_t *) coap_get_app_data(session->context);
	if (dcaf->transactions == NULL) {
		dcaf_log(DCAF_LOG_WARNING, "get_transaction_state: no transaction\n");
		return DCAF_STATE_UNKNOWN;
	}
	return dcaf->transactions->state.act;
}

dcaf_result_t set_transaction_state(coap_session_t *session, dcaf_transaction_state_t state){
	dcaf_context_t *dcaf = (dcaf_context_t *) coap_get_app_data(session->context);
	if (dcaf->transactions == NULL) {
		dcaf_log(DCAF_LOG_WARNING, "set_transaction_state: no transaction\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	dcaf->transactions->state.act = state;
	dcaf_log(DCAF_LOG_INFO,
			"set_transaction_state: transaction state is now %i\n", state);
	return DCAF_OK;
}


dcaf_result_t resolve_address(const char *uristring, coap_address_t *dst) {
	dcaf_result_t res;
	coap_uri_t uri;
	int uri_len = strlen(uristring);
	unsigned char *buf = (unsigned char *) dcaf_alloc_type_len(DCAF_VAR_STRING, uri_len +1);
	if(buf == NULL){
		dcaf_log(DCAF_LOG_ERR, "resolve_address: failed to alloc memory\n");
		return DCAF_ERROR_INTERNAL_ERROR;

	}
	assert(uri_len > 0);
	memcpy(buf, uristring, uri_len + 1);

	if (coap_split_uri(buf, uri_len, &uri) < 0) {
		dcaf_log(DCAF_LOG_CRIT,
				"resolve_address: failed to resolve address\n");
		dcaf_free_type(DCAF_VAR_STRING, buf);
		return DCAF_ERROR_INTERNAL_ERROR;
	}

	res = dcaf_set_coap_address(uri.host.s, uri.host.length, uri.port, dst);
	if (res != DCAF_OK) {
		dcaf_log(DCAF_LOG_CRIT,
				"resolve_address: failed to resolve address\n");
	}
	dcaf_free_type(DCAF_VAR_STRING, buf);
	return res;
}

dcaf_result_t json_to_am_config(json_t *j, am_abc_configuration_st **config){
	if (!json_is_object(j)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_am_config: Invalid JSON\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	json_t *j_iss_path = json_object_get(j, "issuer_path");
	json_t *j_rule_path = json_object_get(j, "rule_path");
	json_t *j_attr_rule_path = json_object_get(j, "attribute_rule_path");
	json_t *j_trust_certs_path = json_object_get(j, "trusted_certificates_path");
	json_t *j_bin_path = json_object_get(j, "abc_binary_path");
	json_t *j_cred_dir_path = json_object_get(j, "credential_path");
	json_t *j_cert_path = json_object_get(j, "certificate_path");
	json_t *j_key_path = json_object_get(j, "private_key_path");
	json_t *j_fifo_path = json_object_get(j, "abc_fifo_path");


	if (!j_iss_path || ! j_rule_path || ! j_attr_rule_path || !j_trust_certs_path || !j_bin_path ||
			!j_cred_dir_path || !j_cert_path || !j_key_path || !j_fifo_path ||
			! json_is_string(j_iss_path) || ! json_is_string(j_rule_path) || ! json_is_string(j_attr_rule_path) ||
			! json_is_string(j_trust_certs_path) || ! json_is_string(j_bin_path) || !json_is_string(j_fifo_path) ||
			! json_is_string(j_cred_dir_path) || ! json_is_string(j_cert_path) || ! json_is_string(j_key_path)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_am_config: Invalid JSON\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	(*config)->abc_binary_path = json_string_value(j_bin_path);
	(*config)->attribute_rule_path =  json_string_value(j_attr_rule_path);
	(*config)->certificate_path =  json_string_value(j_cert_path);
	(*config)->credential_path =  json_string_value(j_cred_dir_path);
	(*config)->issuer_path =  json_string_value(j_iss_path);
	(*config)->private_key_path =  json_string_value(j_key_path);
	(*config)->rule_path =  json_string_value(j_rule_path);
	(*config)->trusted_certificates_path =  json_string_value(j_trust_certs_path);
	(*config)->abc_fifo_path =  json_string_value(j_fifo_path);
	return DCAF_OK;
}

dcaf_result_t transform_nonce(dcaf_nonce_t **transformed_nonce,
		size_t transformed_nonce_len, coap_session_t *session, dcaf_nonce_t *n) {
	*transformed_nonce = dcaf_new_nonce(transformed_nonce_len);
	if (!*transformed_nonce) {
		dcaf_log(DCAF_LOG_ERR, "compute_random: memory allocation failure\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if (!export_keying_material(session,
			(unsigned char *) (*transformed_nonce)->nonce, transformed_nonce_len,
			"EXPERIMENTAL_ABC", 16, n->nonce, n->nonce_length)) {
		dcaf_log(DCAF_LOG_ERR,
				"compute_random: failed to export keying material\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	return DCAF_OK;
}




