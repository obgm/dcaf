/*
 * test_access_rules.cc -- test parsing of rules
 *
 * Copyright (C) 2018-2019 Sara Stadler
 *
 * This file is part of the DCAF library libdcaf. Please see README
 */
#include <jansson.h>
#include <string.h>
#include "test.hh"
#include "catch.hpp"
#include "dcaf/dcaf_abc_json.h"
#include "dcaf/dcaf_rules.h"
#include "dcaf/dcaf_rules_json.h"

SCENARIO( "Parse JSON representations of rules and disclosure proof and match attribute values", "[rules]" ) {
	static std::unique_ptr<rule_list_st, Deleter> rules;
	static std::unique_ptr<attribute_list_st, Deleter> attributes;
	static std::unique_ptr<json_t, Deleter> ruleset;
	static std::unique_ptr<json_t, Deleter> proof;
	static std::unique_ptr<attribute_conditions_st, Deleter> attribute_condition;
	dcaf_result_t res;
	GIVEN("A JOSN file containing rules"){
	json_error_t error;
	json_t *j;
	j = json_load_file("./testconfig/ruleset.json",0, &error);
	REQUIRE(j != nullptr);
	ruleset.reset(j);
	WHEN("json_to_rule_list is called") {
		rule_list_st *result = NULL;
		res = json_to_rule_list(ruleset.get(), &result);
		rules.reset(result);
		THEN("the result is DCAF_OK and a valid rule_list_st is created") {
			REQUIRE(res == DCAF_OK);
			REQUIRE(rules.get() != nullptr);
			REQUIRE(rules.get()->rule.id == 1);
			//permissions
			REQUIRE(rules.get()->rule.permission != nullptr);
			REQUIRE(rules.get()->rule.permission->methods == 1);
			int l = rules.get()->rule.permission->resource_len +1;
			char *buf = (char *)malloc(l);
			memcpy(buf,rules.get()->rule.permission->resource,rules.get()->rule.permission->resource_len +1 );
			REQUIRE(strcmp(buf, "127.0.0.1/premium_family") == 0);
			free(buf);
			//attribute conditions
			REQUIRE(rules.get()->rule.required_attributes != nullptr);
			REQUIRE(rules.get()->rule.required_attributes->credential_id == 1845015144759184385);
			REQUIRE(rules.get()->rule.required_attributes->attributes != nullptr);
			REQUIRE(rules.get()->rule.required_attributes->attributes->attribute.id == 3);
			REQUIRE(rules.get()->rule.required_attributes->attributes->attribute.value == 0);
			REQUIRE(rules.get()->rule.required_attributes->attributes->next->attribute.id == 1);
			REQUIRE(rules.get()->rule.required_attributes->attributes->next->attribute.value == 14126736806326323);

		}
	}
}
	GIVEN("The rule_list_st and a dcaf_aif_permission_t included in the list"){
	dcaf_aif_permission_t *search_again = (dcaf_aif_permission_t *)dcaf_alloc_type(DCAF_AIF_PERMISSIONS);
	search_again->methods = 1;
	const char *url = "127.0.0.1/premium_family";
	memcpy(search_again->resource, url, strlen(url) +1);
	search_again->resource_len = strlen(url) +1;
	WHEN("find_permssions_in_rule_list is called") {
		attribute_conditions_st *conditions = NULL;
		res = find_permssions_in_rule_list(rules.get(), search_again, &conditions);
		THEN("The result is DCAF_OK and a valid attribute_condition_st is created") {
			REQUIRE(res == DCAF_OK);
			REQUIRE(conditions != nullptr);
			REQUIRE(conditions->attributes->attribute.id == 3);
			REQUIRE(conditions->attributes->attribute.value == 0);
			REQUIRE(conditions->attributes->next->attribute.id == 1);
			REQUIRE(conditions->attributes->next->attribute.value == 14126736806326323);
		}
		dcaf_free_type(DCAF_AIF_PERMISSIONS, search_again);
		attribute_condition.reset(conditions);
	}
}
	GIVEN("The rule_list_st and a dcaf_aif_permission_t NOT included in the list"){
	dcaf_aif_permission_t *search = (dcaf_aif_permission_t *)dcaf_alloc_type(DCAF_AIF_PERMISSIONS);
	search->methods = 1;
	const char *url = "127.0.0.1/superduper_family";
	memcpy(search->resource, url, strlen(url) +1);
	search->resource_len = strlen(url) +1;
	WHEN("find_permssions_in_rule_list is called") {
		attribute_conditions_st *c = NULL;
		res = find_permssions_in_rule_list(rules.get(), search, &c);
		THEN("The result is DCAF_NOT_IMPLEMENTED") {
			REQUIRE(res == DCAF_ERROR_NOT_IMPLEMENTED);
		}
	}
	dcaf_free_type(DCAF_AIF_PERMISSIONS, search);
}

	GIVEN("A JSON string containing a disclosure proof on the attributes requested by the valid attribute_condition_st"){
	const char *c = "{\"c\":87000812011707257776273378067995015134243305774902456238270953294129624550901,\"A\":635689251116653329678454366861358379347749137275110180684162237326363326767370056264905636960682597708471310350682243882482126272661895929032380552331861810617746762635569149329151442276958089266255964501342641768925648075428581965814770582971010003752649141269734434453602559203142093130180727137330128654337307404190223689359959070999242899251076756137774162770021485270345696872159220975278269282373772013946373859365024356457204826159946147852514810995178122140385257093171399891570918707236664327452364867661280496781616004760952885622239743798890659652263494155826109454008576098826580869274006148631513820397681951909030198987682398521926362000500766199136064576037311062832154389410532999158558301226369982362933459321206471909599865997869962514327634723163281066763162906981081318626356068409327467730376653834350292576431098459257090156078414736157074269233902779720658797157678717361481598392449227617520544395821698871674663748740626521149536635369599800416897988933713121776453620856055046541806324584538782808498654076760480496382151376641642759453648714309292177549161960449168632962912957332625584389058374406140881491344678963272204334440407746626116900340437316392881881580876776686785402538359823473666742288179401,\"e_response\":40713114285834382450077506002622785920514851586263023725052100082841886955145455542569780556765982029060196657561045190379956917691328188900392664682431,\"v_response\":-71787098312250311422993882086309396467834766125225315492772870523478183768012543387933530259462920242357421460131153850938699335668794220763565368106665847467328962397658030494955022002327056370493148323095184505388218752582826453403280642103822265444715583335702421124555782682275852845846767784524400620316221544502271204447041079696052157899577239233064070286862446531551904753930332734298654997696798242889313068744869444055965329409633566600606001951058875856810104628800398980477751072284030195265884260940405414614715188617826196891933346757537877338990933411655426293866887381533214570194928706739338739968292049990865460808878326251754735700968460685917711997533249807227069577408889686379898262172543989291016635391571116951173373249439453771170516904424846468973318356587978498852182455477160404986921825144345645777519185970210500362046413014421240753426953606369754617822234141812614027427923516124859750320924498164770138286333857602624991611095366718310613421607157485817235687617001976380737957348605342448379923425288789149999487165015105362007029672185994458579880643695546390745931029652839225604663022842030776532602642961790255364114392309800077393414954452960154797025974465245705307919809540661983284155523762097555744394928369473592777364704115302441542695601080448339505256573239225320801928622309329897331721581416704097896243612386379067479399678505973329103343052562436677781255730424092865189282974280074959873152993920948683620954819144040545063819095832533093709170484017454702454173110064432478818428794211294950969728400242551791719052032540593034416895158399160958022915976463908347911,\"a_responses\":{\"0\":258144711550061927848293999984201217427067197629039160409406175279837445527594606098569913215148499988502107456033311282250500638097575700137253805897963682624446182470352709831865012937835635421869257691873221983447514135588810704493645348262707111059460010775941146135,\"2\":444664740769302082982415086854232576685139803241147659525004374107142392916658011088850030762767747522210175352449775337949601221793960183925243702173503727800625101684329233329822106261055899455010393626185347930639898314696748599133220814693193653052686668994047854747},\"a_disclosed\":{\"1\":14126736806326323,\"3\":0}}";
	str_st *s = dcaf_new_str(strlen(c) + 1);
	REQUIRE(s != nullptr);
	REQUIRE(s->val != nullptr);
	memcpy(s->val, c, strlen(c) + 1);
	WHEN("get_disclosed_attributes_from_proof is called") {
		attribute_list_st *result = NULL;
		res = get_disclosed_attributes_from_proof(s, &result);
		dcaf_delete_str(s);
		attributes.reset(result);
		THEN("the result is DCAF_OK and a valid attribute_list_st is created") {
			REQUIRE(res == DCAF_OK);
			REQUIRE(attributes.get() != nullptr);
			REQUIRE(attributes.get()->attribute.id == 3);
			REQUIRE(attributes.get()->attribute.value == 0);
			REQUIRE(attributes.get()->next->attribute.id == 1);
			REQUIRE(attributes.get()->next->attribute.value == 14126736806326323);
		}
	}

}
	GIVEN("the valid attribute_condition_st and the matching attribute_list_st extracted from the proof"){
	WHEN(" compare_attributes is called") {
		REQUIRE(attribute_condition.get() != nullptr);
		REQUIRE(attributes.get() != nullptr);
		res = compare_attributes(attribute_condition.get(), attributes.get());
		THEN("The result code is DCAF_OK") {
			REQUIRE(res == DCAF_OK);
		}

	}
}
}

SCENARIO( "Parse JSON representations of rules requiring no attribute values to be disclosed", "[rules_empty]" ) {
	static std::unique_ptr<rule_list_st, Deleter> rules;
	static std::unique_ptr<attribute_list_st, Deleter> attributes;
	static std::unique_ptr<json_t, Deleter> ruleset;
	dcaf_result_t res;
	GIVEN("A JSON file containing rules "){
	json_error_t error;
	json_t *j;
	j = json_load_file("./testconfig/ruleset_empty.json",0, &error);
	REQUIRE(j != nullptr);
	ruleset.reset(j);
	WHEN("json_to_rule_list is called") {
		rule_list_st *result;
		res = json_to_rule_list(ruleset.get(), &result);
		rules.reset(result);
		THEN("the result is DCAF_OK and a valid rule_list_st is created") {
			REQUIRE(res == DCAF_OK);
			REQUIRE(rules.get() != nullptr);
			//attribute conditions
			REQUIRE(rules.get()->rule.required_attributes != nullptr);
			REQUIRE(rules.get()->rule.required_attributes->credential_id == 1845015144759184385);
			REQUIRE(rules.get()->rule.required_attributes->attributes == nullptr);
		}
	}
}
	GIVEN("The rule_list_st and a dcaf_aif_permission_t included in the list"){
	dcaf_aif_permission_t *search = (dcaf_aif_permission_t *)dcaf_alloc_type(DCAF_AIF_PERMISSIONS);
	search->methods = 1;
	const char *url = "127.0.0.1/premium_family";
	memcpy(search->resource, url, strlen(url) +1);
	search->resource_len = strlen(url) +1;
	WHEN("find_permssions_in_rule_list is called") {
		attribute_conditions_st *conditions = NULL;
		res = find_permssions_in_rule_list(rules.get(), search, &conditions);
		THEN("The result is DCAF_OK and a valid attribute_conditions_st is created") {
			REQUIRE(res == DCAF_OK);
			REQUIRE(conditions != nullptr);
			REQUIRE(conditions->credential_id == 1845015144759184385);
			REQUIRE(conditions->attributes == NULL);
		}
	}
	dcaf_free_type(DCAF_AIF_PERMISSIONS, search);
}

}

SCENARIO( "Parse JSON representations of attribute rules and search for attribute flags", "[attr_rules]" ) {
	static std::unique_ptr<attribute_rule_list_st, Deleter> attr_rules;
	static std::unique_ptr<json_t, Deleter> attr_ruleset;
	static std::unique_ptr<attribute_permission_list_st, Deleter> attr_permissions;
	dcaf_result_t res;
	GIVEN("A JSON file containing attribute rules "){
	json_error_t error;
	json_t *j;
	j = json_load_file("./testconfig/attribute_ruleset.json",0, &error);
	REQUIRE(j != nullptr);
	attr_ruleset.reset(j);
	WHEN("json_to_attribute_rule_list is called") {
		attribute_rule_list_st *result;
		res = json_to_attribute_rule_list(attr_ruleset.get(), &result);
		attr_rules.reset(result);
		THEN("the result is DCAF_OK and a valid rule_list_st is created") {
			REQUIRE(res == DCAF_OK);
			REQUIRE(attr_rules.get() != nullptr);
			REQUIRE(attr_rules.get()->rule.id == 1);
			//permissions
			REQUIRE(attr_rules.get()->rule.permissions != nullptr);
			REQUIRE(attr_rules.get()->rule.permissions->permission.credetnial_id == 1);
			REQUIRE(attr_rules.get()->rule.permissions->permission.attribute_flag == 3);
			REQUIRE(attr_rules.get()->rule.permissions->next != nullptr);
			REQUIRE(attr_rules.get()->rule.permissions->next->permission.credetnial_id == 1845015144759184385);
			REQUIRE(attr_rules.get()->rule.permissions->next->permission.attribute_flag == 7);
			REQUIRE(attr_rules.get()->rule.required_certificate_len != 0);
			REQUIRE(strcmp(attr_rules.get()->rule.required_certificate, "7344849bce72811c2430bb77de3f42a342c5a19c") == 0);
		}
	}
	GIVEN("The rulelist and a fingerprint contained in the list") {
		const char *fingerprint = "7344849bce72811c2430bb77de3f42a342c5a19c";
		WHEN("find_attribute_permssions_in_rule_list is called") {
			attribute_permission_list_st *attr_result;
			attr_result = find_attribute_permssions_in_rule_list(attr_rules.get(), (char *)fingerprint);
			THEN("A valid attribute_permission_list_st is returned ") {
				REQUIRE(attr_result != nullptr);
				REQUIRE(attr_result->permission.attribute_flag == 3);
				REQUIRE(attr_result->permission.credetnial_id == 1);
			}
			attr_permissions.reset(attr_result);
		}
		GIVEN("The attribute_permission_list_st") {
			WHEN("search_attribute_permsissions is called for included flags") {
				THEN("DCAF_OK is returned") {
					REQUIRE(attr_permissions.get() != nullptr);
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1, 3) == DCAF_OK);
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1, 1) == DCAF_OK);
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1, 2) == DCAF_OK);
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1, 0) == DCAF_OK); //as this means generating an empty proof
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1845015144759184385, 7) == DCAF_OK);//1,2,3
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1845015144759184385, 1) == DCAF_OK);//1
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1845015144759184385, 2) == DCAF_OK);//2
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1845015144759184385, 3) == DCAF_OK);//1,2
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1845015144759184385, 4) == DCAF_OK);//3
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1845015144759184385, 5) == DCAF_OK);//1,3
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1845015144759184385, 6) == DCAF_OK);//2,3
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1845015144759184385, 0) == DCAF_OK);//as this means generating an empty proof
				}
			}
			WHEN("search_attribute_permsissions is called for flags that are not included") {
				THEN("DCAF_ERROR_UNAUTHORIZED  is returned") {
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1, 4) == DCAF_ERROR_UNAUTHORIZED);
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1, 5) == DCAF_ERROR_UNAUTHORIZED);
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1, 6) == DCAF_ERROR_UNAUTHORIZED);
					REQUIRE(search_attribute_permsissions(attr_permissions.get(), 1, 7) == DCAF_ERROR_UNAUTHORIZED);

				}
			}
		}
	}
}
}

