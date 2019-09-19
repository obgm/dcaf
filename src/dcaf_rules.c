/*
 * dcaf_rules.c -- rule sets for DCAF authorization managers using attribute-based credentials
 *
 * Copyright (C) 2018-2019 Sara Stadler
 *
 * This file is part of the DCAF library libdcaf. Please see README
 */

#include "dcaf/dcaf_rules.h"


rule_list_st *
dcaf_new_rule_list(void) {
	rule_list_st *r = dcaf_alloc_type(DCAF_RULE_LIST);
	if (r) {
		memset(r, 0, sizeof(rule_list_st));
	}
	return r;
}

void dcaf_delete_rule_list(rule_list_st *r) {
	rule_list_st *item, *tmp;

	LL_FOREACH_SAFE(r, item, tmp)
	{
		if (item->rule.required_attributes != NULL) {
			if (item->rule.required_attributes->attributes != NULL) {
				dcaf_delete_attribute_list(
						item->rule.required_attributes->attributes);
			}
				dcaf_free_type(DCAF_ATTRIBUTE_CONDITIONS,item->rule.required_attributes);
		}
		if (item->rule.permission != NULL) {
			dcaf_free_type(DCAF_AIF_PERMISSIONS, item->rule.permission);
		}
		dcaf_free_type(DCAF_RULE_LIST, item);

	}
}

attribute_permission_list_st *
dcaf_new_attribute_permission_list(void){
	attribute_permission_list_st *r = dcaf_alloc_type(DCAF_ATTRIBUTE_PERMISSION_LIST);
	if (r) {
		memset(r, 0, sizeof(attribute_permission_list_st));
	}
	return r;
}

void
dcaf_delete_attribute_permission_list(attribute_permission_list_st *r){
	attribute_permission_list_st *item, *tmp;
	LL_FOREACH_SAFE(r, item, tmp)
			{
				dcaf_free_type(DCAF_ATTRIBUTE_PERMISSION_LIST, item);
			}
}

attribute_rule_list_st *
dcaf_new_attribute_rule_list(void){
	attribute_rule_list_st *r = dcaf_alloc_type(DCAF_ATTRIBUTE_RULE_LIST);
		if (r) {
			memset(r, 0, sizeof(attribute_rule_list_st));
		}
		return r;
}

void
dcaf_delete_attribute_rule_list(attribute_rule_list_st *r){
	attribute_rule_list_st *item, *tmp;

		LL_FOREACH_SAFE(r, item, tmp)
		{
			if(item->rule.permissions != NULL){
				dcaf_delete_attribute_permission_list(item->rule.permissions);
			}
			if(item->rule.required_certificate != NULL){
				dcaf_free_type(DCAF_VAR_STRING,item->rule.required_certificate);
			}
			dcaf_free_type(DCAF_ATTRIBUTE_RULE_LIST, item);
		}
}



dcaf_result_t find_permssions_in_rule_list(rule_list_st *r,
		dcaf_aif_permission_t *permission, attribute_conditions_st **conditions) {
	rule_list_st *el;
	rule_st *matching = NULL;
	*conditions = NULL;
	LL_FOREACH(r,el)
	{
		if (el->rule.permission->methods == permission->methods) {
			if (strcmp((const char *) el->rule.permission->resource, (const char *)permission->resource)
					== 0) {
				matching = &(el->rule);
			}
		}
	}
	if(matching != NULL){
		*conditions = matching->required_attributes;
		return DCAF_OK;
	}
	return DCAF_ERROR_NOT_IMPLEMENTED;
}

attribute_permission_list_st *find_attribute_permssions_in_rule_list(attribute_rule_list_st *r, char *cert_fingerprint) {
	attribute_rule_list_st *el;
	LL_FOREACH(r,el)
	{
		if (strcmp(el->rule.required_certificate, cert_fingerprint) == 0) {
			return el->rule.permissions;
		}
	}
	return NULL;
}


static attribute_st
*find_attribute_by_id(attribute_list_st *a, int id) {
	attribute_list_st *el;
	LL_FOREACH(a, el)
	{
		if (el->attribute.id == id) {
			return &(el->attribute);
		}
	}
	return NULL;
}

dcaf_result_t
find_required_attributes(rule_list_st *rules, dcaf_aif_t *aif, uint64_t *cred_id, uint *attribute_flag){
	*cred_id = 0;
	*attribute_flag = 0;
	dcaf_aif_t *el;
	dcaf_result_t res;
	LL_FOREACH(aif, el)
	{
		attribute_conditions_st *condition;
		if ((res= find_permssions_in_rule_list(rules, &(el->perm), &condition)) != DCAF_OK)
			return res;
		if (condition == NULL) {
			dcaf_log(DCAF_LOG_INFO,
					"find_required_attributes: No rules configured for the requested permission\n");
			return DCAF_OK;
		}
		if (*cred_id == 0) {
			*cred_id = condition->credential_id;
		} else if (condition->credential_id != *cred_id) {
			dcaf_log(DCAF_LOG_ERR,
					"find_required_attributes: Requesting attributes from multiple credential is not supported\n");

			return DCAF_ERROR_NOT_IMPLEMENTED;
		}
		attribute_list_st *al;
		LL_FOREACH(condition->attributes, al)
		{
			switch (al->attribute.id) {
			case 1:
				*attribute_flag |= 1;
				break;
			case 2:
				*attribute_flag |= 2;
				break;
			case 3:
				*attribute_flag |= 4;
				break;
			case 4:
				*attribute_flag |= 8;
				break;
			default:
				dcaf_log(DCAF_LOG_ERR,
									"find_required_attributes: Requested attribute id is not supported\n");
				return DCAF_ERROR_NOT_IMPLEMENTED;
			}
		}
	}
	return DCAF_OK;
}


dcaf_result_t
check_attribute_conditions(rule_list_st *rules, dcaf_aif_t *aif, attribute_list_st *disclose_attributes, uint64_t *cred_id){
	dcaf_aif_t *el;
	*cred_id = 0;
	dcaf_result_t res;
	LL_FOREACH(aif, el)
	{
		attribute_conditions_st *condition;
		if((res = find_permssions_in_rule_list(rules, &(el->perm), &condition))!= DCAF_OK)
			return res;
		if (*cred_id == 0) {
			*cred_id = condition->credential_id;
		} else if (condition->credential_id != *cred_id) {
			dcaf_log(DCAF_LOG_ERR,
					"check_attribute_conditions: Requesting attributes from multiple credential is not supported\n");
			return DCAF_ERROR_NOT_IMPLEMENTED;
		}
		if (compare_attributes(condition, disclose_attributes) != DCAF_OK) {
			dcaf_log(DCAF_LOG_ERR,
					"check_attribute_conditions: Attributes do not match\n");
			return DCAF_ERROR_UNAUTHORIZED;
		}
	}
	return DCAF_OK;
}


dcaf_result_t compare_attributes(attribute_conditions_st *requested,
		attribute_list_st *given) {
	attribute_list_st *el;
	if(given == NULL && requested->attributes != NULL){
		return DCAF_ERROR_UNAUTHORIZED;
	}
	LL_FOREACH(requested->attributes, el)
	{
		attribute_st *a = find_attribute_by_id(given, el->attribute.id);
		if (a == NULL || a->value != el->attribute.value) {
			dcaf_log(DCAF_LOG_WARNING, "compare_attributes: attribute values do not match.\n.");
			return DCAF_ERROR_UNAUTHORIZED;
		}
	}
	return DCAF_OK;
}

/*
 * Searches the given attribute_permission_list_st for the element with the given credential id.
 * Returns the element if exists, NULL otherwise.
 */
static attribute_permission_st *
find_attribute_permission_by_cred_id(attribute_permission_list_st *permissions, uint64_t cred_id){
	attribute_permission_list_st *el;
	LL_FOREACH(permissions, el)
	{
		if(el->permission.credetnial_id == cred_id){
			return &(el->permission);
		}
	}
	return NULL;
}

/*
 * Compares the two binary attribute flags and returns DCAF_OK if given_attributes
 * includes requested_attributes. Returns  DCAF_ERROR_UNAUTHORIZED otherwise.
 */
static dcaf_result_t
check_attributes_include(int granted_attributes, int requested_attributes){
	if((granted_attributes & requested_attributes) == requested_attributes){
		return DCAF_OK;
	}
	return DCAF_ERROR_UNAUTHORIZED;
}

dcaf_result_t
search_attribute_permsissions(attribute_permission_list_st *granted_permissions, uint64_t cred_id, int attributes){
	attribute_permission_st *permission = find_attribute_permission_by_cred_id(granted_permissions, cred_id);
	if(permission == NULL){
		dcaf_log(DCAF_LOG_WARNING, "compare_attribute_permsissions: no permissions granted for credential id %" PRIu64 ".\n.", cred_id);
		return DCAF_ERROR_UNAUTHORIZED;
	}
	return check_attributes_include(permission->attribute_flag, attributes);
}

