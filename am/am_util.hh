/*
 * Created by Sara Stadler 2018/2019
 */

#ifndef AM_COAP_UTIL_HH_
#define AM_COAP_UTIL_HH_
#include <random>
#include <jansson.h>
#include <string.h>
#include "dcaf/dcaf_int.h"
#include <coap2/coap.h>
#include "dcaf/dcaf.h"

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef empty_string
#define empty_string(a) (strcmp(a, "") == 0)
#endif

/*
 * An AM can act as CAM, SAM or both.
 */
typedef enum{
	DCAF_UNKNOWN_AM,
	DCAF_SAM,
	DCAF_CAM,
	DCAF_BOTH
}dcaf_am_type_t;

/*
 * Represents the configuration of an AM using attribute-based credentials for mutual authentication
 * and authorization.
 */
typedef struct am_abc_configuration_st{
	const char *issuer_path; //path to the issuer directory containing credential descriptions and public keys for all supported issuers
	const char *rule_path; //path to the json file containing the ruleset (SAM)
	const char *attribute_rule_path; //path to the json file containing the attribute ruleset (CAM)
	const char *trusted_certificates_path; //path to the directory containing the trusted certificate or to a particular certificate file (CAM)
	const char *credential_path;//path to the directory containing the credentials (CAM)
	const char *certificate_path;//path to the X509 certificate to use in the handshake (SAM)
	const char *private_key_path;//path to the private key corresponding to the X509 certificate (SAM)
	const char *abc_binary_path; //path to the binary of the irma_tool
	const char *abc_fifo_path; //path to the pipe where irma_tool output is written
}am_abc_configuration_st;


am_abc_configuration_st*
dcaf_new_am_abc_configuration(void);

void
dcaf_delete_am_abc_configuration(am_abc_configuration_st *a);

/*
 * Calls coap_run_once until the transaction state is set to either
 * DCAF_STATE_TICKET_GRANT or DCAF_STATE_UNAUTHORIZED.
 * This function is taken (and slightly modified) from the libcoap client example.
 */
int run_and_wait(coap_context_t *ctx, coap_session_t *session, int wait_seconds);

/*
 * Generates an new PDU, sets the type to COAP_MESSAGE_NON, sets a new
 * random token and a new transaction id.
 * Returns the new pdu.
 */
coap_pdu_t *generate_pdu(coap_session_t *session);

/*
 * Random function taken from the dcaf am example
 * */
void rnd(uint8_t *out, size_t len);

dcaf_transaction_state_t get_transaction_state(coap_session_t *session);

dcaf_result_t set_transaction_state(coap_session_t *session, dcaf_transaction_state_t state);

/*
 * Splits the given uri string of format schema://host[...] and
 * saves the result in dst.
 */
dcaf_result_t resolve_address(const char *uristring, coap_address_t *dst);

/*
 * Parses the @p json object to an am_abc_configuration_st and stores the result in @p config.
 * Returns DCAF_OK if the parsing succeeds, DCAF_ERROR_INTERNAL_ERROR otherwise.
 * @param j the json object to parse
 * @param config the resulting am configuration
 */
dcaf_result_t json_to_am_config(json_t *j, am_abc_configuration_st **config);


#endif /* AM_COAP_UTIL_HH_ */
