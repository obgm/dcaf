/*
 * Created by Sara Stadler 2018/2019
 */
#include <stdio.h>
#include <string.h>
#include "test.hh"
#include "catch.hpp"
#include "dcaf/cose.h"
#include "dcaf/dcaf.h"
#include "dcaf/dcaf_am.h"
#include "coap2/net.h"
#include "dcaf/dcaf_abc.h"
#include "dcaf/dcaf_directory_traverser.h"

SCENARIO( "Generation and parsing of CBOR messages related to attribute based authorization", "[abc_message]" ) {
	static std::unique_ptr<dcaf_attribute_request_t, Deleter> areq;
	static std::unique_ptr<coap_pdu_t, Deleter> coap_pdu;
	static std::unique_ptr<coap_pdu_t, Deleter> coap_response;
	static std::unique_ptr<dcaf_nonce_t, Deleter> n;
	static std::unique_ptr<credential_list_st, Deleter> credentials_mes;

	GIVEN("A valid nonce, credential id and attribute flag"){
	dcaf_nonce_t *n1 = dcaf_new_nonce(DCAF_MAX_NONCE_SIZE);
	dcaf_prng(n1->nonce, n1->nonce_length);
	n.reset(n1);
	WHEN("dcaf_set_attribute_info is called") {
		dcaf_result_t res;
		init_abc_configuration("../go/irmatool", "../go/pipe");
		coap_pdu.reset(coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU));
		REQUIRE(coap_pdu.get() != nullptr);
		res = dcaf_set_attribute_info(coap_pdu.get(), 1845015144759184385, 4, n1);
		THEN("The response code is DCAF_OK and a COAP PDU with payload and with code 204 is created") {
			REQUIRE(res == DCAF_OK);
			REQUIRE(coap_pdu.get()->code == COAP_RESPONSE_CODE(204));
			REQUIRE(coap_pdu.get()->data != NULL);
		}
	}
}

	GIVEN("The PDU and a valid credential list"){
		credential_list_st *cred_list = NULL;
		credential_st cred;
		issuer_st *i= (issuer_st *)dcaf_alloc_type(DCAF_ISSUER);
		i->id  = 1845015144759184384;
		i->public_key = NULL;
		i->public_key_length = 4096;
		i->public_key_path_length = 0;
		cred.id = 1845015144759184385;
		cred.issuer = i;
		credential_list_st *credential_list = dcaf_new_credential_list();
		credential_list->credential = cred;
		LL_PREPEND(cred_list, credential_list);
		credentials_mes.reset(cred_list);
	WHEN("dcaf_parse_attribute_info is called") {
		dcaf_attribute_request_t *result;
		dcaf_result_t res;
		res = dcaf_parse_attribute_info(coap_pdu.get(), &result, credentials_mes.get());
		THEN("The response code is DCAF_OK and an attribute request with the required fields has been created") {
			REQUIRE(res == DCAF_OK);
			REQUIRE(result != nullptr);
			REQUIRE(memcmp(result->n->nonce, n.get()->nonce, 8) == 0);
			REQUIRE(result->cred_id == 1845015144759184385);
			REQUIRE(result->atributes == 4);
			areq.reset(result);
		}
	}
	GIVEN("The attribute request such as the corresponding credential and issuers public key") {
		WHEN("When dcaf_set_disclosure_proof is called") {
			dcaf_result_t res;
			coap_response.reset(coap_pdu_init(0, 0, 5, 8192));
			res = dcaf_set_disclosure_proof(areq.get()->atributes, areq.get()->n, coap_response.get(), "credentials/parksmart_member_credential.json","testkeys/ipk_parksmart_4096.json" );
			THEN("The response code is DCAF_OK and a COAP PDU with payload and with code COAP_REQUEST_POST is created") {
				REQUIRE(res == DCAF_OK);
				REQUIRE(coap_response.get()->code == COAP_REQUEST_POST);
				REQUIRE(coap_response.get()->data != NULL);
			}
		}
		GIVEN("THE PDU") {
			WHEN("dcaf_parse_disclosure_proof is called") {
				dcaf_result_t res;
				str_st *proofstring;
				res = dcaf_parse_disclosure_proof(coap_response.get(), &proofstring);
				THEN("The the result is DCAF_OK and the resulting proof string can be verified") {
					REQUIRE(res == DCAF_OK);
					REQUIRE(proofstring != nullptr);
					REQUIRE(verify_proof("testkeys/ipk_parksmart_4096.json", n.get(), proofstring) == DCAF_OK);

				}
				if(proofstring != NULL) {
					dcaf_delete_str(proofstring);
				}
			}
		}
	}
}

}

