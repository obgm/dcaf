/*
 * dcaf_directory_traverser.c -- functions to traverse config directories
 *
 * Copyright (C) 2018-2019 Sara Stadler
 *
 * This file is part of the DCAF library libdcaf. Please see README
 */

#include "dcaf/dcaf_directory_traverser.h"

credential_list_st *tmp_credential_descriptios;
credential_store_st *tmp_credential_store;


static int
read_file(const char *path, char **buf){
	int ret = DCAF_ERROR_INTERNAL_ERROR;
	size_t chunk = DCAF_CREDEDITAL_MAX_BUF_SIZE;
	FILE *file;
	size_t nread = 0;
	*buf = dcaf_alloc_type_len(DCAF_VAR_STRING, chunk);
	if (*buf == NULL) {
		dcaf_log(DCAF_LOG_ERR, "read_file: Memory allocation failed\n");
		return ret;
	}
	file = fopen(path, "r");
	if (file) {
		nread = fread(*buf, 1, chunk, file);
		if (nread < chunk - 1) {
			(*buf)[nread] = '\0';
			ret = DCAF_OK;

		} else {
			dcaf_log(DCAF_LOG_ERR, "read_file: Error reading file\n");
			dcaf_free_type(DCAF_VAR_STRING,*buf);
		}
	}
	fclose(file);
	return ret;
}

static int
load_credential_description(const char *path, credential_st *result){
	int res;
	json_error_t error;
		json_t *j;
		j = json_load_file(path, 0, &error);
		if(j == NULL){
			dcaf_log(DCAF_LOG_ERR,"load_credential_description: Failed to load: %s %s\n", path, error.text);
			return DCAF_ERROR_INTERNAL_ERROR;
		}
		res = json_to_credential(j, result);
		json_decref(j);
		return res;
}

/*
 * Always returns 0 as ftw breaks otherwise.
 */
static int load_credential_descriptions(const char * path, const struct stat * attribute, int flag){
	(void)attribute;
	if(flag == FTW_F){ //is a regular file
		if(strstr(path, "credential_descriptions") == NULL){
			return DCAF_OK;
		}
		credential_st credential;
		if (DCAF_OK == load_credential_description(path, &credential)) {
			credential_list_st *credential_list = dcaf_new_credential_list();
			credential_list->credential = credential;
			LL_PREPEND(tmp_credential_descriptios, credential_list);
			return DCAF_OK;
		}
		dcaf_log(DCAF_LOG_WARNING, "load_credential_descriptions: file %s could not be loaded. Skip file.\n", path);
		return DCAF_OK;
	}
	dcaf_log(DCAF_LOG_DEBUG, "load_credential_descriptions: file %s is not a regular file. Skip file.\n", path);
	return DCAF_OK;
}

/*
 * Always returns 0 as ftw breaks otherwise.
 */
static int locate_credentials(const char * path, const struct stat * attribute, int flag){
	(void)attribute;
	if(flag == FTW_F){ //is a regular file
		char *buf;
		read_file(path, &buf);
		uint64_t id = extract_credential_id_from_credentialstring(buf);
		dcaf_free_type(DCAF_VAR_STRING,buf);
		if (id != 0) {
			credential_store_st *credential_store = dcaf_new_credential_store();
			credential_store->credential_location.id = id;
			credential_store->credential_location.path_length = strlen(path);
			memset(credential_store->credential_location.path, 0, DCAF_MAX_PATH_LENGTH);
			memcpy(credential_store->credential_location.path, path, credential_store->credential_location.path_length);


			LL_PREPEND(tmp_credential_store, credential_store);
			return DCAF_OK;
		}
		dcaf_log(DCAF_LOG_WARNING, " locate_credentials: file %s could not be parsed. Skip file.\n", path);
		return DCAF_OK;
	}
	dcaf_log(DCAF_LOG_DEBUG, " locate_credentials: file %s is not a regular file. Skip file.\n", path);
	return DCAF_OK;
}

dcaf_result_t traverse_issuer_directory(const char *path, credential_list_st **list){
	*list = NULL;
	if(ftw(path, load_credential_descriptions, 16) == 0){
		*list = tmp_credential_descriptios;
		return DCAF_OK;
	}
	dcaf_log(DCAF_LOG_ERR, " traverse_issuer_directory: failed to load credential descriptions.\n");
	return DCAF_ERROR_INTERNAL_ERROR;
}

dcaf_result_t traverse_credential_directory(const char *path, credential_store_st **list){
	*list = NULL;
	if(ftw(path, locate_credentials, 16) == 0){
		*list = tmp_credential_store;
		return DCAF_OK;
	}
	dcaf_log(DCAF_LOG_ERR, "traverse_credential_directory: failed to initialize credential store.\n");
	return DCAF_ERROR_INTERNAL_ERROR;
}

