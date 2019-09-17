/*
 * dcaf_rules_json.h -- functions for json parsing
 *
 * Copyright (C) 2018-2019 Sara Stadler
 *
 * This file is part of the DCAF library libdcaf. Please see README
 */
#ifndef _DCAF_DCAF_RULES_JSON_H_
#define _DCAF_DCAF_RULES_JSON_H_ 1

#ifdef __cplusplus
extern "C" {
#ifdef EMACS_NEEDS_A_CLOSING_BRACKET
}
#endif
#endif

#include <jansson.h>
#include <stdlib.h>
#include "dcaf/dcaf_rules.h"
#include "dcaf/dcaf_abc.h"
#include "dcaf/dcaf_abc_json.h"


/**
 * Parses the @p json object to a rule_list_st and stores the result in @p r.
 * Only on success memory is allocated for r and has to be freed by calling
 * dcaf_delete_rule_list().
 * @return DCAF_OK if the parsing succeeds, DCAF_ERROR_INTERNAL_ERROR otherwise.
 * @param j The json object to parse
 * @param c The resulting rule list
 */
dcaf_result_t json_to_rule_list(json_t *j, rule_list_st **r);


/**
 * Parses the @p json object to an attribute_rule_list_st and stores the result in @p r.
 * Only on success memory is allocated for r and has to be freed by calling
 * dcaf_delete_attribute_rule_list().
 * @return  DCAF_OK if the parsing succeeds, DCAF_ERROR_INTERNAL_ERROR otherwise.
 * @param j The json object to parse
 * @param c The resulting attribute rule list
 */
dcaf_result_t json_to_attribute_rule_list(json_t *j, attribute_rule_list_st **r);


#ifdef __cplusplus
}
#endif


#endif /* INCLUDE_DCAF_DCAF_RULES_JSON_H_ */
