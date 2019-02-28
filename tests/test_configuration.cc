/*
 * Created by Sara Stadler 2018/2019
 */

#include <stdio.h>
#include <string.h>
#include "test.hh"
#include "catch.hpp"
#include "dcaf/dcaf_abc.h"
#include "dcaf/dcaf_abc_json.h"
#include "dcaf/dcaf_directory_traverser.h"

SCENARIO( "Traverse issuers directory and parse credential descriptions", "[traverse]" ) {
	static std::unique_ptr<credential_list_st, Deleter> credentials;
	dcaf_result_t res;
	GIVEN("The path to the issuer directory"){
		const char *path = "./testconfig/issuers";
		WHEN("traverse_issuer_directory is called"){
			credential_list_st *result;
			res = traverse_issuer_directory(path, &result);
			credentials.reset(result);
			THEN("The result code is DCAF_OK and a valid credential_list_st is created"){
				REQUIRE(res == DCAF_OK);
				REQUIRE(credentials.get() != nullptr);
				REQUIRE(credentials.get()->credential.id == 1845015144759184385);
				REQUIRE(credentials.get()->credential.issuer != nullptr);
				REQUIRE(credentials.get()->credential.issuer->id == 1845015144759184384);
				REQUIRE(strcmp(credentials.get()->credential.issuer->public_key, "./ipk.json") == 0);
				//should have 4 elements
				REQUIRE(credentials.get()->next != nullptr);
				REQUIRE(credentials.get()->next->next != nullptr);
				REQUIRE(credentials.get()->next->next->next != nullptr);
			}
		}
	}
}
SCENARIO( "Extract credential id from string representation of credential", "[extract]" ) {
	GIVEN("A credential as JSON string"){
		const char *s = "{\"gabi_cred\":{\"signature\":{\"A\":15473695676304900946003092116198870042613241361749873063602286994334135672706927077553075271991089310921229141003721973434016504202833987532278421415439287347125184771766317968258433070074452704610683068933698013779431481839038579210894047417861017120052896048875529995141759699045830908756397289133359984415,\"e\":259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930268486010616692955275388065407890481,\"v\":41471670386426283420178024153120713803084706494828722268365466158356074697892364306963458034660011900473092646307390921972803527820259605841517519065720841790462045794159667226712196768927364892280298724939776550753255991845189225033685943097480632747626321217595075405703964062830239292787987276775507128540007422854590659858415654923959388393254884629425604984879834594711273396680061507174592774517566675007112700103215194607983728749824054815013159090713329603578120017039085340654249546668467755733975084506,\"KeyshareP\":null},\"attributes\":[31842421075113257807093948949102093553722554674349968865953654128357830620699,31650977344484717,40233,112568633486457,0]},\"meta\":{\"id\":566,\"name\":\"test credential\",\"issuer\":\"parkcheaper\"}}";
		WHEN("Textract_credential_id_from_credentialstring is called"){
			int id;
			id = extract_credential_id_from_credentialstring((char *)s);
			THEN("A valid id is obtained"){
				REQUIRE(id == 566);
			}
		}
	}
}

SCENARIO( "Traverse credential directory and fill the credential store", "[traverse_cred]" ) {
	static std::unique_ptr<credential_store_st, Deleter> credentials;
	dcaf_result_t res;
	GIVEN("The path to the credential directory"){
		const char *path = "./credentials";
		WHEN("traverse_credential_directory is called"){
			credential_store_st *result;
			res = traverse_credential_directory(path, &result);
			credentials.reset(result);
			THEN("The result is DCAF_OK and a valid credential_list_st is created"){
				REQUIRE(res == DCAF_OK);
				//must contain 2 elements
				REQUIRE(credentials.get() != nullptr);
				REQUIRE(credentials.get()->next != nullptr);
			}
		}
	}
}


