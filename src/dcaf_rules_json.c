/*
 * dcaf_rules_json.c -- functions for json parsing
 *
 * Copyright (C) 2018-2019 Sara Stadler
 *
 * This file is part of the DCAF library libdcaf. Please see README
 */

#include "dcaf/dcaf_rules_json.h"

static dcaf_result_t json_to_attribute_permission(json_t *j, attribute_permission_st *p) {
	if (!json_is_object(j)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_attribute_permission: Invalid Json\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	json_t *j_cred_id = json_object_get(j, "credential_id");
	json_t *j_attributes = json_object_get(j, "attributes");
	if (!j_cred_id || !j_attributes || !json_is_number(j_cred_id) ||
	!json_is_number(j_attributes)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_attribute_permission: Invalid Json\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	p->attribute_flag = json_integer_value(j_attributes);
	p->credetnial_id = json_integer_value(j_cred_id);
	return DCAF_OK;
}

static dcaf_result_t
json_to_attribute_permission_list(json_t *j, attribute_permission_list_st **r) {
	size_t i;
	json_t *v;
	*r = NULL;
	json_array_foreach(j, i, v)
	{
		attribute_permission_list_st *attr_perm_list = dcaf_new_attribute_permission_list();
		attribute_permission_st attr_perm;
		if (DCAF_OK != json_to_attribute_permission(v, &attr_perm)) {
			dcaf_log(DCAF_LOG_ERR, "json_to_attribute_rule_list: Cannot parse rule\n.");
			dcaf_delete_attribute_permission_list(attr_perm_list);
			dcaf_delete_attribute_permission_list(*r);
			return DCAF_ERROR_INTERNAL_ERROR;
		}

		attr_perm_list->permission = attr_perm;
		LL_PREPEND(*r, attr_perm_list);
	}
	return DCAF_OK;
}



static dcaf_result_t json_to_attribute_rule(json_t *j, attribute_rule_st *r) {
	if (!json_is_object(j)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_attribute_rule: Invalid Json\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	json_t *j_id = json_object_get(j, "id");
	json_t *j_attr_permissions = json_object_get(j, "attribute_permissions");
	json_t *j_cert_condition = json_object_get(j, "certificate_condition");
	if (!j_id || !json_is_number(j_id)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_attribute_rule: Invalid Json\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if(!j_cert_condition || !json_is_string(j_cert_condition)){
		dcaf_log(DCAF_LOG_ERR, "json_to_attribute_rule: Invalid Json\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}

	if (!j_attr_permissions) {
		dcaf_log(DCAF_LOG_ERR, "json_to_attribute_rule: Invalid Json\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}

	attribute_permission_list_st *attr_permissions = NULL;
	if (json_to_attribute_permission_list(j_attr_permissions, &attr_permissions) != DCAF_OK) {
		 dcaf_log(DCAF_LOG_ERR, "json_to_attribute_rule: Cannot parse permission\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}

	r->id = json_integer_value(j_id);
	r->permissions = attr_permissions;
	r->required_certificate_len =  strlen(json_string_value(j_cert_condition));
	if((r->required_certificate =  dcaf_alloc_type_len(DCAF_VAR_STRING, r->required_certificate_len + 1)) == NULL){
		 dcaf_log(DCAF_LOG_ERR, "json_to_attribute_rule: Memory allocation failed\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	memcpy(r->required_certificate, json_string_value(j_cert_condition), r->required_certificate_len + 1);
	return DCAF_OK;
}

dcaf_result_t json_to_attribute_rule_list(json_t *j, attribute_rule_list_st **r) {
	size_t i;
	json_t *v;
	*r = NULL;
	json_array_foreach(j, i, v)
	{
		attribute_rule_list_st *attr_rule_list = dcaf_new_attribute_rule_list();
		if(attr_rule_list == NULL){
			dcaf_log(DCAF_LOG_ERR, "json_to_attribute_rule_list: Failed to allocated memory\n.");
			dcaf_delete_attribute_rule_list(*r);
			return DCAF_ERROR_INTERNAL_ERROR;
		}
		attribute_rule_st attr_rule;
		if (DCAF_OK != json_to_attribute_rule(v, &attr_rule)) {
			dcaf_log(DCAF_LOG_ERR, "json_to_attribute_rule_list: Cannot parse rule\n.");
			dcaf_delete_attribute_rule_list(attr_rule_list);
			dcaf_delete_attribute_rule_list(*r);
			return DCAF_ERROR_INTERNAL_ERROR;
		}

		attr_rule_list->rule = attr_rule;
		LL_PREPEND(*r, attr_rule_list);
	}
	return DCAF_OK;
}


static dcaf_result_t json_to_aif_permission(json_t *j, dcaf_aif_permission_t *p) {
	if (!json_is_object(j)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_aif_permission: Invalid Json\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	json_t *j_resource = json_object_get(j, "resource");
	json_t *j_methods = json_object_get(j, "methods");
	if (!j_resource || !j_methods || !json_is_string(j_resource) ||
	!json_is_number(j_methods)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_aif_permission: Invalid Json\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	int jlen = strlen(json_string_value(j_resource));
	p->resource_len = jlen;
	int len = jlen <= DCAF_MAX_RESOURCE_LEN ? jlen : DCAF_MAX_RESOURCE_LEN;
	memcpy(p->resource, json_string_value(j_resource), len + 1);
	p->methods = json_integer_value(j_methods);
	return DCAF_OK;
}


static dcaf_result_t json_to_attribute_conditions(json_t *j,
		attribute_conditions_st *a) {
	json_t *j_credential_id;
	json_t *j_attributes;
	attribute_list_st *attributes = NULL;
	if (!json_is_object(j)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_attribute_conditions: Invalid Json\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	j_credential_id = json_object_get(j, "credential_id");
	j_attributes = json_object_get(j, "attributes");

	if (!j_credential_id || !json_is_number(j_credential_id) || !j_attributes || !json_is_array(j_attributes) ) {
		dcaf_log(DCAF_LOG_ERR, "json_to_attribute_conditions: Invalid Json\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}

	if (json_array_size(j_attributes) == 0) {
		dcaf_log(DCAF_LOG_INFO, "json_to_attribute_conditions: No attribute disclosure required\n.");
	}
	else{
		if (json_to_attribute_list(j_attributes, &attributes) != DCAF_OK) {
			dcaf_log(DCAF_LOG_ERR,
					"json_to_attribute_conditions: Cannot parse attributes\n.");
			return DCAF_ERROR_INTERNAL_ERROR;
		}
	}
	a->credential_id = json_integer_value(j_credential_id);
	a->attributes = attributes;

	return DCAF_OK;
}

static dcaf_result_t json_to_rule(json_t *j, rule_st *r) {
	if (!json_is_object(j)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_rule: Invalid Json\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}

	json_t *j_id = json_object_get(j, "id");
	json_t *j_permission = json_object_get(j, "permission");
	json_t *j_attribute_conditions = json_object_get(j, "attribute_conditions");
	if (!j_id || !json_is_number(j_id)) {
		dcaf_log(DCAF_LOG_ERR, "json_to_rule: Invalid Json\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}

	if (!j_permission || !j_attribute_conditions) {
		dcaf_log(DCAF_LOG_ERR, "json_to_rule: Invalid Json\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}

	dcaf_aif_permission_t *permission = dcaf_alloc_type(DCAF_AIF_PERMISSIONS);
	if (permission == NULL) {
		dcaf_log(DCAF_LOG_ERR, "json_to_rule: Memory allocation failed\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if (json_to_aif_permission(j_permission, permission) != DCAF_OK) {
		dcaf_free_type(DCAF_AIF_PERMISSIONS,permission);
		 dcaf_log(DCAF_LOG_ERR, "json_to_rule: Cannot parse permission\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	attribute_conditions_st *required_attributes = dcaf_alloc_type(DCAF_ATTRIBUTE_CONDITIONS);
	if (required_attributes == NULL) {
		dcaf_log(DCAF_LOG_ERR, "json_to_rule: Memory allocation failed\n.");
		dcaf_free_type(DCAF_AIF_PERMISSIONS,permission);
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if (json_to_attribute_conditions(j_attribute_conditions,
			required_attributes) != DCAF_OK) {
		dcaf_free_type(DCAF_AIF_PERMISSIONS,permission);
		dcaf_free_type(DCAF_ATTRIBUTE_CONDITIONS, required_attributes);
		dcaf_log(DCAF_LOG_ERR, "json_to_rule: Cannot parse attributes\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	r->id = json_integer_value(j_id);
	r->permission = permission;
	r->required_attributes = required_attributes;
	return DCAF_OK;
}

dcaf_result_t json_to_rule_list(json_t *j, rule_list_st **r) {
	size_t i;
	json_t *v;
	*r = NULL;
	json_array_foreach(j, i, v)
	{
		rule_list_st *rule_list = dcaf_new_rule_list();
		if(rule_list == NULL){
			dcaf_log(DCAF_LOG_ERR, "json_to_rule_list: Failed to allocate memory\n.");
			dcaf_delete_rule_list(*r);
			return DCAF_ERROR_INTERNAL_ERROR;
		}
		rule_st rule;
		if (DCAF_OK != json_to_rule(v, &rule)) {
			dcaf_log(DCAF_LOG_ERR, "json_to_rule_list: Cannot parse rule\n.");
			dcaf_delete_rule_list(rule_list);
			dcaf_delete_rule_list(*r);
			return DCAF_ERROR_INTERNAL_ERROR;
		}

		rule_list->rule = rule;
		LL_PREPEND(*r, rule_list);
	}
	return DCAF_OK;
}


