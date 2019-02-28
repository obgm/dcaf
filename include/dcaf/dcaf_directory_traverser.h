/*
 * Created by Sara Stadler 2018/2019
 */

#ifndef _DCAF_DCAF_DIRECTORY_TRAVERSER_H_
#define _DCAF_DCAF_DIRECTORY_TRAVERSER_H_ 1

#ifdef __cplusplus
extern "C" {
#ifdef EMACS_NEEDS_A_CLOSING_BRACKET
}
#endif
#endif

#include <ftw.h> //traverse file hierarchy

#include <jansson.h>
#include "dcaf/dcaf_abc.h"
#include "dcaf/dcaf_abc_json.h"

/**
 * Traverses the directory specified by @p path, parses all contained credential
 * descriptions and stores the result in @p list.
 * The method succeeds if the directory can be traversed even if (some) descriptions
 * cannot be parsed. Errors that occur parsing particular files are logged.
 * Only on success memory is allocated for list and has to be freed by calling
 * dcaf_delete_rule_list().
 * @return DCAF_OK if the parsing succeeds, DCAF_ERROR_INTERNAL_ERROR otherwise.
 * @param path The directory to traverse
 * @param c The resulting credential list
 */
dcaf_result_t traverse_issuer_directory(const char *path, credential_list_st **list);


/**
 * Traverses the directory specified by @p path, parses all contained credentials
 * and stores their id and storage path in @p store.
 * The method succeeds if the directory can be traversed even is (some) credentials
 * cannot be parsed. Errors that occur parsing particular files are logged.
 * Only on success memory is allocated for list and has to be freed by calling
 * dcaf_delete_rule_list.
 * @return DCAF_OK if the parsing succeeds, DCAF_ERROR_INTERNAL_ERROR otherwise.
 * @param path The directory to traverse
 * @param c The resulting credential store
 */
dcaf_result_t traverse_credential_directory(const char *path, credential_store_st **store);

#ifdef __cplusplus
}
#endif

#endif /* _DCAF_DCAF_DIRECTORY_TRAVERSER_H_ */
