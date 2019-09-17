/*
 * dcaf_rules.h -- rule sets for DCAF authorization managers using attribute-based credentials
 *
 * Copyright (C) 2018-2019 Sara Stadler
 *
 * This file is part of the DCAF library libdcaf. Please see README
 */

#ifndef _DCAF_DCAF_RULES_H_
#define _DCAF_DCAF_RULES_H_ 1

#ifdef __cplusplus
extern "C" {
#ifdef EMACS_NEEDS_A_CLOSING_BRACKET
}
#endif
#endif

#include <jansson.h>
#include <stdlib.h>
#include "dcaf/aif.h"
#include "dcaf/utlist.h"
#include "dcaf/dcaf_abc.h"
#include "dcaf/dcaf_abc_json.h"


/**
 *Combines a particular credential type and expected attribute values
 */
typedef struct attribute_conditions_st{
	uint64_t credential_id;
	attribute_list_st *attributes;

}attribute_conditions_st;

/**
 *Relates access permissions to the respective attribute conditions
 */
typedef struct rule_st{
	int id;
	dcaf_aif_permission_t *permission;
	attribute_conditions_st *required_attributes;

}rule_st;

/** A list of rule_st */
typedef struct rule_list_st {
  struct rule_list_st *next;
  rule_st rule;
} rule_list_st;

/**
 * Combines a particular credential type and a binary flag for the attribute values
 * that can be requested
 */
typedef struct attribute_permission_st{
	uint64_t credetnial_id;
	int attribute_flag;
}attribute_permission_st;

/** A list of attribute_permission_st*/
typedef struct attribute_permission_list_st {
  struct attribute_permission_list_st *next;
  attribute_permission_st permission;
}attribute_permission_list_st;

/*
 * Relates permission to request attribute values to a certificate fingerprint
 */
typedef struct attribute_rule_st{
	int id;
	attribute_permission_list_st *permissions;
	char *required_certificate;
	int required_certificate_len;
}attribute_rule_st;

/** A list of attribute_rule_st*/
typedef struct attribute_rule_list_st {
  struct attribute_rule_list_st *next;
  attribute_rule_st rule;
}attribute_rule_list_st;



attribute_rule_list_st *
dcaf_new_attribute_rule_list(void);

void
dcaf_delete_attribute_rule_list(attribute_rule_list_st *r);

attribute_permission_list_st *
dcaf_new_attribute_permission_list(void);

void
dcaf_delete_attribute_permission_list(attribute_permission_list_st *r);

rule_list_st *
dcaf_new_rule_list(void);

void
dcaf_delete_rule_list(rule_list_st *r);


/**
 * Determines which attributes are needed according to the requested permissions.
 * Valid attribute ids are ored to the flag.
 * @return DCAF_ERROR_NOT_IMPLEMENTED if @p permission is not contained in the list,
 * 			in case an invalid attribute id (any id > 4) is requested or if
 *  		attributes from more than one credential are requested, DCAF_OK otherwise.
 *  @param rules The rule_list_st relating @p permissions and required attributes
 *  @param permissions The dcaf_aif_t containing the permissions
 *  @param cred_id Pointer to the storage where the id of the credential containing the needed attributes will be stored
 *  @param attribute_flag Pointer to the storage where the binary flag for the needed attribute indices will be stored
 */
dcaf_result_t
find_required_attributes(rule_list_st *rules, dcaf_aif_t *permissions, uint64_t *cred_id, uint *attribute_flag);


/**
 * Checks weather the attribute values in @p disclosed_attributes match the values configured in @p rules
 * needed to obtain the permissions specified by @p permission.
 * @return DCAF_OK if the values match, DCAF_ERROR_UNAUTHORIZED
 * 			if they do not match and DCAF_ERROR_NOT_IMPLEMENTED if attributes from more than one credential are required according to
 * 			@p rules or if the @p permission is not included in the rule list.
 * *@param rules The rule_list_st relating @p permissions and required attributes
 *  @param permissions The dcaf_aif_t containing the permissions
 *  @param disclosed_attributes The attribute_list_st containing the disclosed attributes
 *  @param cred_id Pointer to the storage where the id of the credential containing attributes will be stored
 *  			(as this is needed for disclosure proof verification afterwards)
 *  */
dcaf_result_t
check_attribute_conditions(rule_list_st *rules, dcaf_aif_t *permission, attribute_list_st *disclose_attributes, uint64_t *cred_id);

/**
 * Iterates the given @p attribute_rule_list and searches for the given_certificate _fingerprint.
 * @return  The attribute_permissions_list_st corresponding to the fingerprint if
 * 			it exists an NULL otherwise.
 * @param attribute_rule_list The list to search
 * @param certificate_fingerprint The fingerprint to search for
 */
attribute_permission_list_st *find_attribute_permssions_in_rule_list(attribute_rule_list_st *attribute_rule_list, char *certificate_fingerprint);

/**
 * Iterates the @p granted_permissions and checks weather they include the requested @p attributes for the credential with
 * the given @p credential_id.
 * @return DCAF_OK if the attributes are included,  DCAF_ERROR_UNAUTHORIZED otherwise.
 * @param granted_permissions The permission list to search
 * @param  credential_id The credential id to search for
 * @param attributes The attribute flag to compare to the flag included in the permission if any
 */
dcaf_result_t search_attribute_permsissions(attribute_permission_list_st *granted_permissions, uint64_t credential_id, int atributes);

/**
 * Iterates the given @p rule_list and searches for the given @p permission.
 * Sets @p conditions to  the attribute_consitions_st corresponding to the permission if it exists.
 * @return DCAF_OK on success DCAF_ERROR not implemented otherwise
 * @param rule_list The rule list to search
 * @param permission The permission to search for
 * @parma conditions Pointer to the struct for storing the result
 */
dcaf_result_t find_permssions_in_rule_list(rule_list_st *rule_list, dcaf_aif_permission_t *permission, attribute_conditions_st **conditions);


/**
 * Compares the @p given attribute_list_st to @p requested attribute_consditions_st.
 * @return DCAF_OK if attribute indices and values match, DCAF_ERROR_UNAUTHORIZED otherwise.
 * @param requested The attributes_condistion_st containing the requested attributes
 * @param given The attribute_list_st containing the given attributes
 */
dcaf_result_t compare_attributes(attribute_conditions_st *requested, attribute_list_st *given);

#ifdef __cplusplus
}
#endif


#endif /* INCLUDE_DCAF_DCAF_RULES_H_ */
