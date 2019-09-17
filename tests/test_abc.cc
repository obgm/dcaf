/*
 * test_abc.cc -- test generation and verification of selective disclosure proofs on attribute based credentials
 *
 * Copyright (C) 2018-2019 Sara Stadler
 *
 * This file is part of the DCAF library libdcaf. Please see README
 */
#include <stdio.h>
#include <string.h>
#include "test.hh"
#include "catch.hpp"
#include "dcaf/dcaf_abc.h"

SCENARIO( "Generation and verification of selective disclosure proofs on attribute based credentials", "[abc]" ) {
	static std::unique_ptr<dcaf_nonce_t, Deleter> n;
	static std::unique_ptr<str_st, Deleter> disclosure_proof;
	static std::unique_ptr<str_st, Deleter> empty_proof;
	dcaf_result_t res;
	init_abc_configuration("../go/irmatool", "../go/pipe");
	GIVEN("A valid credential, the issuers public key and a nonce."){
	str_st *proof = NULL;
	dcaf_nonce_t *n1 = dcaf_new_nonce(10);
	REQUIRE(n1 != nullptr);
	dcaf_prng(n1->nonce, n1->nonce_length);
	n.reset(n1);
	WHEN("generate_proof is called for some attributes on the credential") {
		res = generate_proof("credentials/parksmart_member_credential.json", "testkeys/ipk_parksmart_4096.json", n.get(), 4, &proof);
		THEN("The result is DCAF_OK and a proof has been generated.") {
			REQUIRE(res == DCAF_OK);
			REQUIRE(proof != nullptr);
		}
		disclosure_proof.reset(proof);
	}
}
	GIVEN("The disclosure proof"){
	WHEN("verify_proof is called for the same nonce and issuers public key") {
		res = verify_proof("testkeys/ipk_parksmart_4096.json", n.get(), disclosure_proof.get());
		THEN("THE result code is DCAF_OK") {
			REQUIRE(res == DCAF_OK);
		}

	}
	WHEN("verify_proof is called for a different nonce") {
		dcaf_nonce_t *n2 = dcaf_new_nonce(DCAF_MAX_NONCE_SIZE);
		REQUIRE(n2 != nullptr);
		dcaf_prng(n2->nonce, n2->nonce_length);
		res =verify_proof("testkeys/ipk_parksmart_4096.json", n2, disclosure_proof.get());
		THEN("The result code is DCAF_ERROR_UNAUTHORIZED") {
			REQUIRE(res == DCAF_ERROR_UNAUTHORIZED);
		}
		if(n2 != NULL) {
			dcaf_free_type(DCAF_NONCE, n2);
		}
	}
	WHEN("verify_proof is called for a different issuers public key") {
		res =verify_proof("testkeys/ipk2.json", n.get(), disclosure_proof.get());
		THEN("The result code is DCAF_ERROR_UNAUTHORIZED") {
			REQUIRE(res == DCAF_ERROR_UNAUTHORIZED);
		}
	}

}
	GIVEN("A valid credential, the issuers public key and a nonce."){
	str_st *empty;
	WHEN("generate_proof is called with the attribute flag set to 0") {
		res = generate_proof("credentials/parksmart_member_credential.json", "testkeys/ipk_parksmart_4096.json", n.get(), 0, &empty);
		THEN("The result is DCAF_OK and a proof has been generated.") {
			REQUIRE(res == DCAF_OK);
			REQUIRE(empty != nullptr);
		}
		empty_proof.reset(empty);
	}


	GIVEN("The EMPTY disclosure proof"){
		WHEN("verify_proof is called for the same nonce and issuers public key") {
			res = verify_proof("testkeys/ipk_parksmart_4096.json", n.get(), empty_proof.get());
			THEN("THE result code is DCAF_OK") {
				REQUIRE(res == DCAF_OK);
			}

		}
	}
}
	GIVEN("A valid credential and issuers public key."){
		str_st *p;
		WHEN("generate_proof is called with the nonce parameter set to nullptr") {
			res = generate_proof("credentials/parksmart_member_credential.json", "testkeys/ipk_parksmart_4096.json", nullptr, 4, &p);
			THEN("The result is DCAF_ERROR_INTERNAL_ERROR") {
				REQUIRE(res == DCAF_ERROR_INTERNAL_ERROR);
			}
		}
	}
}

