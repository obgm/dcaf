/*
 * Created by Sara Stadler 2018/2019
 */

#include "dcaf/dcaf_abc_json.h"

static dcaf_result_t
json_to_attribute(json_t *j, attribute_st *a){
	if (!json_is_object(j)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_attribute: Invalid Json JSON\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	json_t *j_id = json_object_get(j, "id");
	json_t *j_value = json_object_get(j, "value");
	if (!j_id || !json_is_number(j_id)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_attribute: Invalid Json JSON\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if (!j_value || !json_is_number(j_value)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_attribute: Invalid Json JSON\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
		}
	a->id = json_integer_value(j_id);
	a->value = json_integer_value(j_value);
	return DCAF_OK;
}

dcaf_result_t  json_to_attribute_list(json_t *j, attribute_list_st **a){
	size_t i;
	json_t *v;
	*a = NULL;
	json_array_foreach(j, i, v)
	{
		attribute_list_st *attribute_list = dcaf_new_attribute_list();
		attribute_st attribute;
		if (0 != json_to_attribute(v, &attribute)) {
			dcaf_log(DCAF_LOG_ERR, "json_to_attribute_list: Json parsing of attribute failed\n.");
			dcaf_delete_attribute_list(*a);
			dcaf_delete_attribute_list(attribute_list);
			return DCAF_ERROR_INTERNAL_ERROR;
		}
		attribute_list->attribute = attribute;
		LL_PREPEND(*a, attribute_list);
	}
	return DCAF_OK;
}

static dcaf_result_t
json_to_issuer(json_t *j, issuer_st *i){
	if (!json_is_object(j)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_issuer: Invalid json\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	json_t *j_id = json_object_get(j, "issuer_id");
	json_t *j_key = json_object_get(j, "public_key");
	json_t *j_key_len = json_object_get(j, "public_key_length");
	if (!j_id || !json_is_number(j_id)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_issuer: Invalid json\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if (!j_key || !json_is_string(j_key)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_issuer: Invalid json\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if (!j_key_len || !json_is_number(j_key_len)) {
			dcaf_log(DCAF_LOG_ERR, "json_to_issuer: Invalid json\n");
			return DCAF_ERROR_INTERNAL_ERROR;
	}

	i->id = json_integer_value(j_id);
	i->public_key_length = json_integer_value(j_key_len);
	i->public_key_path_length = strlen(json_string_value(j_key));
	if((i->public_key = dcaf_alloc_type_len(DCAF_VAR_STRING, i->public_key_path_length + 1)) == NULL){
		dcaf_log(DCAF_LOG_ERR, "json_to_issuer: Memory allocation failed\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	memcpy(i->public_key, json_string_value(j_key), i->public_key_path_length +1);
	return DCAF_OK;
}

dcaf_result_t json_to_credential(json_t *j, credential_st *c){
	if (!json_is_object(j)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_credential: Invalid json\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	json_t *j_id = json_object_get(j, "credential_id");
	json_t *j_issuer = json_object_get(j, "issuer");
	if (!j_id || !json_is_number(j_id)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_credential: Invalid json\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if(!j_issuer){
		dcaf_log(DCAF_LOG_ERR, "json_to_credential: Invalid json\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	issuer_st *issuer = dcaf_alloc_type(DCAF_ISSUER);
	if(issuer == NULL){
		dcaf_log(DCAF_LOG_ERR, "json_to_credential: Memory allocation failure.\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if(json_to_issuer(j_issuer, issuer) != DCAF_OK){
		dcaf_log(DCAF_LOG_ERR, "json_to_credential: Json parsing of issuer failed..\n");
		dcaf_free_type(DCAF_ISSUER, issuer);
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	c->id = json_integer_value(j_id);
	c->issuer = issuer;
 return DCAF_OK;
}



static dcaf_result_t
json_dislosed_attributes_to_attribute_list(json_t *j, attribute_list_st **a){
	if (!json_is_object(j)) {
		dcaf_log(DCAF_LOG_ERR, "json_dislosed_attributes_to_attribute_list: Invalid json\n");
		return DCAF_ERROR_BAD_REQUEST;
	}
	*a = NULL;
	for(int i = 1; i < 5;i++){
		char s[2];
		s[0] = i + 48;
		s[1] = 0;
		json_t *j_value = json_object_get(j, s);
		if(j_value){
			attribute_list_st * attribute_list = dcaf_new_attribute_list();
			attribute_list->attribute.id = i;
			if(json_is_integer(j_value)){
				dcaf_log(DCAF_LOG_DEBUG, "json_dislosed_attributes_to_attribute_list: add attribute value %lld\n", json_integer_value(j_value));
				attribute_list->attribute.value = json_integer_value(j_value);
				LL_PREPEND(*a, attribute_list);
			}
			else{
				dcaf_log(DCAF_LOG_ERR, "json_dislosed_attributes_to_attribute_list: Invalid json\n");
				dcaf_delete_attribute_list(*a);
				dcaf_delete_attribute_list(attribute_list);
				return DCAF_ERROR_BAD_REQUEST;
			}

		}
		else{
			dcaf_log(DCAF_LOG_DEBUG, "json_dislosed_attributes_to_attribute_list: no attribute value for index %i\n", i);
		}
	}
	return DCAF_OK;
}

static dcaf_result_t
extract_disclosed_attributes_from_proofstring(char *p, char **s){
	char *substring = strstr(p, "a_disclosed");
	if(substring == NULL){
		dcaf_log(DCAF_LOG_INFO, "extract_disclosed_attributes_from_proofstring: No attributes disclosed.\n");
		return DCAF_OK;
	}
	substring += 13;

	int len = strlen(substring);
	*s = dcaf_alloc_type_len(DCAF_VAR_STRING, len);
	if(*s == NULL){
		dcaf_log(DCAF_LOG_ERR, "extract_disclosed_attributes_from_proofstring: Memory allocation failed.\n");
		return DCAF_ERROR_INTERNAL_ERROR;

	}
	memcpy(*s, substring, len -1);
	(*s)[len -1] = '\0';
	return DCAF_OK;
}

dcaf_result_t get_disclosed_attributes_from_proof(str_st *proof, attribute_list_st **result){
	dcaf_result_t res;
	json_error_t error;
	json_t *j;
	char *buf = NULL;
	if((res = extract_disclosed_attributes_from_proofstring(proof->val, &buf) != DCAF_OK))
		return res;

	if(buf == NULL){
		result = NULL;
		return DCAF_OK;
	}
	//TODO load integer as string once this has been implemented in jansson
	//see https://github.com/akheron/jansson/issues/10
	if (!(j = json_loads(buf, 0, &error))) {
		dcaf_log(DCAF_LOG_ERR, "get_disclosed_attributes_from_proof: Could not load json: %s\n", error.text);
		dcaf_free_type(DCAF_VAR_STRING, buf);
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	dcaf_free_type(DCAF_VAR_STRING, buf);
	res = json_dislosed_attributes_to_attribute_list(j, result);
	json_decref(j);
	return res;
}



uint64_t extract_credential_id_from_credentialstring(char *p){
	uint64_t res = 0;
	char *substring = strstr(p, "meta");
	if (substring == NULL) {
		dcaf_log(DCAF_LOG_ERR, "extract_credential_id_from_credentialstring: Cannot extract id.\n");
		return 0;
	}
	//go to beginning of id value
	substring += 12;
	int len = 0;
	while(isdigit(*substring) != 0){
		len++;
		substring++;
	}
	substring--;
	for(int i = 0; i < len; i++){
		uint64_t val = pow(10,i) * (*(substring - i) - '0');
		res += val;
	}
	return res;
}
