/*
 * dcaf_abc_json.h -- functions for json parsing
 *
 * Copyright (C) 2018-2019 Sara Stadler
 *
 * This file is part of the DCAF library libdcaf. Please see README
 */

#ifndef _DCAF_DCAF_ABC_JSON_H_
#define _DCAF_DCAF_ABC_JSON_H_ 1


#ifdef __cplusplus
extern "C" {
#ifdef EMACS_NEEDS_A_CLOSING_BRACKET
}
#endif
#endif

#include <jansson.h>
#include <inttypes.h>
#include <math.h>
#include <ctype.h>
#include "dcaf/dcaf_abc.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/utlist.h"

/**
 * Parses the @p json object to a credential_st and stores the result in @p c.
 * On success the the function allocates memory for the issuer_st in c.
 * This has to be freed by calling dcaf_delete_issuer().
 * @return DCAF_OK if the parsing succeeds, DCAF_ERROR_INTERNAL_ERROR otherwise.
 * @param j the json object to parse
 * @param c the resulting credential
 */
dcaf_result_t  json_to_credential(json_t *j, credential_st *c);


/**
 * Parses the @p json object to an attribute_list_st and stores the result in @p a.
 * On success memory is allocated for a and has to be freed by calling
 * dcaf_delete_attribute_list().
 * @return DCAF_OK if the parsing succeeds, DCAF_ERROR_INTERNAL_ERROR otherwise.
 * @param j the json object to parse
 * @param a the resulting attribute list
 */
dcaf_result_t  json_to_attribute_list(json_t *j, attribute_list_st **a);

/**
 * Given the @p json representation of a credential, this method
 * extracts the credential id.
 * @return 0 if no id can be extracted, the id otherwise.
 * @param credential the credential as json string
 */
uint64_t extract_credential_id_from_credentialstring(char *credential);


/**
 * Given the json representation of an attribute proof, this method
 * extracts the @p disclosed_attributes.
 * On success memory is allocated for a and has to be freed by calling
 * dcaf_delete_attribute_list().
 * @return DCAF_OK if the attributes can be extracted, DCAF_ERROR_INTERNAL_ERROR if an error occurs
 * and DCAF_ERROR_BAD_REQUEST is the proof cannot be parsed properly
 * @param proof the proof as json string
 * @param disclosed_attributes the resulting attribute list
 */
dcaf_result_t get_disclosed_attributes_from_proof(str_st *proof, attribute_list_st **disclosed_attributes);


#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_DCAF_DCAF_ABC_JSON_H_ */
