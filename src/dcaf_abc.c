/*
 * dcaf_abc.c -- functions related to attribute-based credentials
 *
 * Copyright (C) 2018-2019 Sara Stadler
 *
 * This file is part of the DCAF library libdcaf. Please see README
 */

#include <jansson.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h> //pipe
#include<sys/stat.h>
#include <stdint.h>
#include<math.h>


#include "dcaf/dcaf_abc.h"

const char *binary_path = NULL;
//where the output of the binary is written to
const char *fifo = NULL;

str_st *
dcaf_new_str(int len){
	str_st * ret = dcaf_alloc_type(DCAF_STRING_STR);
	if(ret){
		ret->val = dcaf_alloc_type_len(DCAF_VAR_STRING, len);
		if(ret->val == NULL){
			dcaf_free_type(DCAF_STRING_STR,ret);
			return NULL;
		}
		ret->len = len;
	}
	return ret;
}
void
dcaf_delete_str(str_st* s){
	if(s != NULL){
		if(s->val != NULL){
			dcaf_free_type(DCAF_VAR_STRING, s->val);
		}
		dcaf_free_type(DCAF_STRING_STR,s);
	}
}

attribute_list_st *
dcaf_new_attribute_list(void) {
attribute_list_st *a = dcaf_alloc_type(DCAF_ATTRIBUTE_LIST);
  if (a) {
    memset(a, 0, sizeof(attribute_list_st));
  }
  return a;
}

void
dcaf_delete_attribute_list(attribute_list_st *a) {
  attribute_list_st *item, *tmp;

  LL_FOREACH_SAFE(a, item, tmp){
    dcaf_free_type(DCAF_ATTRIBUTE_LIST, item);
  }
}

credential_list_st *
dcaf_new_credential_list(void){
	credential_list_st *c = dcaf_alloc_type(DCAF_CREDENTIAL_LIST);
	if (c) {
		memset(c, 0, sizeof(credential_list_st));
	}
	return c;
}

void dcaf_delete_issuer(issuer_st *issuer){
	if(issuer != NULL){
		if(issuer->public_key != NULL){
			dcaf_free_type(DCAF_VAR_STRING, issuer->public_key);
		}
		dcaf_free_type(DCAF_ISSUER, issuer);
	}
}
void
dcaf_delete_credential_list(credential_list_st *c){
	credential_list_st *item, *tmp;

	LL_FOREACH_SAFE(c, item, tmp)
	{
		dcaf_delete_issuer(item->credential.issuer);
		dcaf_free_type(DCAF_CREDENTIAL_LIST, item);
	}
}

credential_store_st *
dcaf_new_credential_store(void){
	credential_store_st *c = dcaf_alloc_type(DCAF_CREDENTIAL_STORE);
	if (c) {
		memset(c, 0, sizeof(credential_store_st));
	}
	return c;

}
void
dcaf_delete_credential_store(credential_store_st *c){
	credential_store_st *item, *tmp;

	LL_FOREACH_SAFE(c, item, tmp)
	{
		dcaf_free_type(DCAF_CREDENTIAL_STORE, item);
	}
}

issuer_st *find_issuer_by_credential_id(credential_list_st *c, uint64_t cred_id){
	credential_list_st *el;
	LL_FOREACH(c, el){
		if(el->credential.id == cred_id){
			return el->credential.issuer;
		}
	}
	dcaf_log(DCAF_LOG_ERR,"find_issuer_by_credential_id: issuer for credential with "
			"id %"  PRIu64 " not found\n", cred_id);
	return NULL;
}

int get_required_nonce_length_by_credential(credential_list_st *credential_list, uint64_t credential_id){
	issuer_st *i = find_issuer_by_credential_id(credential_list, credential_id);
	if(i == NULL){
		return 0;
	}
	switch(i->public_key_length){
	case 1024:
		return 10;
	case 2048:
		return 16;
	case 4096:
		return 16;
	default:
		dcaf_log(DCAF_LOG_ERR,"get_required_nonce_length_by_credential: unsupported key length "
					"%i", i->public_key_length);
		return 0;
	}
}

char *find_credential_path_by_id(credential_store_st *s, uint64_t cred_id){
	credential_store_st *el;
	LL_FOREACH(s, el){
		if(el->credential_location.id == cred_id){
			return (char *)el->credential_location.path;
		}
	}
	return NULL;
}

/* source: https://zakird.com/2013/10/13/certificate-parsing-with-openssl*/
static void
to_hex(uint8_t * in, char *out, size_t len)
{
	for(size_t i=0; i < len; i++) {
		char *l = (char*) (2*i + ((intptr_t) out));
		sprintf(l, "%02x", in[i]);
	}
	out[2*len] = 0;
}

/*
 * Parses the given attribute flag to the given char **.
 * @param attributes binary flag for attribute indices as int
 * @pram attr_str pointer to the memory where the result is stored.
 * The result is a comma separated string of attribute indices.
 */
static dcaf_result_t
parse_attribute_flag(int attributes, char **attr_str){
	*attr_str = NULL;
		//parse attribute flag
		switch(attributes){
			case 0:
				dcaf_log(DCAF_LOG_INFO,"generate_proof: No attributes selected to disclose. An empty proof will be generated.\n");
				*attr_str = ","; //empty argument
				break;
			case 1:
				*attr_str = "1";
				break;
			case 2:
				*attr_str = "2";
				break;
			case 3:
				*attr_str = "1,2";
				break;
			case 4:
				*attr_str = "3";
				break;
			case 5:
				*attr_str = "1,3";
				break;
			case 6:
				*attr_str = "2,3";
				break;
			case 7:
				*attr_str = "1,2,3";
				break;
			case 8:
				*attr_str = "4";
				break;
			case 9:
				*attr_str = "1,4";
				break;
			case 10:
				*attr_str = "2,4";
				break;
			case 11:
				*attr_str = "1,2,4";
				break;
			case 12:
				*attr_str = "3,4";
				break;
			case 13:
				*attr_str = "1,3,4";
				break;
			case 14:
				*attr_str = "2,3,4";
				break;
			case 15:
				*attr_str = "1,2,3,4";
				break;
			default:
				dcaf_log(DCAF_LOG_ERR,"generate_proof: Attributes selected to disclose are not supported. Proof generation not possible.\n");
				return DCAF_ERROR_INTERNAL_ERROR;
		}

		return DCAF_OK;
}


dcaf_result_t init_abc_configuration(const char *abc_binary_path, const char *fifo_path){
	binary_path =  abc_binary_path;
	fifo = fifo_path;
	return DCAF_OK;
}


/*
 * Executes the go binaries and translates the exit codes
 * returns DCAF_OK on success
 * returns DCAF_ERROR_UNAUTHORIZED on status 1 (verification failure)
 * returns DCAF_ERROR_INTERNAL_ERROR on status 127 (command does not exist)
 * returns DCAF_ERROR_INTERNAL_ERROR on any other status(error)
 *
 */
static int
execute(char * command){
	dcaf_log(DCAF_LOG_INFO, "execute: %s.\n", command);
	int status = WEXITSTATUS( system(command));
	switch(status){
	case 0:
		return DCAF_OK;
	case 1:
		dcaf_log(DCAF_LOG_ERR, "exceute: status %i proof did not verify.\n", status);
		return DCAF_ERROR_UNAUTHORIZED;
	case 127:
		dcaf_log(DCAF_LOG_ERR, "exceute: status %i no such command.\n", status);
		return DCAF_ERROR_INTERNAL_ERROR;
	default:
		dcaf_log(DCAF_LOG_ERR, "exceute: status %i command execution failes.\n", status);
		return DCAF_ERROR_INTERNAL_ERROR;
	}
}


dcaf_result_t generate_proof(const char *credential_file, const char *public_key_file, dcaf_nonce_t  *n1, int attributes, str_st **proof){
	int ret;
	char *attr_str = NULL;
	const char *command_str;
	size_t command_length;
	FILE *file;
	int fd;
	char *nonce;
	if(binary_path == NULL || fifo == NULL){
		dcaf_log(DCAF_LOG_ERR, "generate_proof: Missing configuration. Proof generation not possible\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if(credential_file == NULL || public_key_file == NULL || n1 == NULL){
		dcaf_log(DCAF_LOG_ERR,"generate_proof: Missing arguments. Proof generation not possible!\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if((ret = parse_attribute_flag(attributes, &attr_str)) != DCAF_OK)
			return ret;

	if((nonce = dcaf_alloc_type_len(DCAF_VAR_STRING, (n1->nonce_length * 2) + 1)) == NULL){
		dcaf_log(DCAF_LOG_ERR,"generate_proof: Memory allocation failed. Proof generation not possible!\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	to_hex(n1->nonce, nonce,n1->nonce_length);

	command_str = "%s proof -c %s -k %s -n %s -a %s -p %s";
	command_length = strlen(binary_path) + strlen(credential_file)
			+ strlen(nonce) + strlen(public_key_file)
			+ strlen(fifo) + strlen(attr_str) + strlen(command_str) - 12 + 1;
	char command[command_length];
	snprintf(command, command_length, command_str,
	binary_path, credential_file, public_key_file, nonce ,attr_str, fifo);
	free(nonce);
	//create and open fifo to read output
	ret = mkfifo(fifo, 0666);
	fd=open(fifo, O_NONBLOCK);
	if(fd == 0){
		dcaf_log(DCAF_LOG_ERR,"generate_proof: Could not open fifo\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}

	//execute binary
	if((ret = execute(command)) != DCAF_OK){
		goto unlink_fifo;
	}

	//associate stream with file descriptior.
	file = fdopen(fd, "r");
	if(file == NULL){
		dcaf_log(DCAF_LOG_ERR, "generate_proof: Could not open fifo\n");
		goto unlink_fifo;
	}

	//Read the first line containing the filesize
	char file_size[20];
	if(fgets(file_size, 20, file) == NULL){
		dcaf_log(DCAF_LOG_ERR,"generate_proof: Error reading proof size.\n");
		goto error;
	}
	int proof_size = atoi(file_size) + 1;
	dcaf_log(DCAF_LOG_DEBUG,"Read proof of size %i\n", proof_size);

	if((*proof = dcaf_new_str(proof_size)) == NULL){
		dcaf_log(DCAF_LOG_ERR,"generate_proof: Memory allocation failure\n");
		goto error;
	}
	int n = fread((*proof)->val, 1,  proof_size, file);
	if(!feof(file)){
		dcaf_log(DCAF_LOG_ERR,"generate_proof: Error reading proof.\n");
		dcaf_delete_str(*proof);
		goto error;
	}

	(*proof)->len = (unsigned int)n+1;
	((*proof)->val)[n] = '\0';

	fclose(file);
	unlink(fifo);
	return DCAF_OK;

	error:
	fclose(file);
	unlink_fifo:
	unlink(fifo);
	return DCAF_ERROR_INTERNAL_ERROR;
}


dcaf_result_t verify_proof(const char *public_key_file, dcaf_nonce_t  *n1, str_st *proof){
	char *nonce1;

	if(binary_path == NULL){
		dcaf_log(DCAF_LOG_ERR,"verify_proof: Missing configuration path. Proof verification not possible\n.");
		return DCAF_ERROR_INTERNAL_ERROR;
	}
	if(public_key_file == NULL || proof->val == NULL || n1 == NULL){
		dcaf_log(DCAF_LOG_ERR,"verify_proof: Missing arguments. Proof verification not possible!\n");
			return DCAF_ERROR_INTERNAL_ERROR;
		}
	if((nonce1 = dcaf_alloc_type_len(DCAF_VAR_STRING, (2 *n1->nonce_length) +1)) == NULL){
		dcaf_log(DCAF_LOG_ERR,"verify_proof: Memory allocation failed\n");
		return DCAF_ERROR_INTERNAL_ERROR;
	}

	to_hex(n1->nonce, nonce1, n1->nonce_length);
	const char *command_str = "%s verify -k %s -n %s -p \'%s\'";
	size_t command_length = strlen(binary_path) + +strlen(nonce1)
			+ strlen(public_key_file) + proof->len + strlen(command_str)
			- 9 + 1;
	char command[command_length];
	snprintf(command, command_length, command_str, binary_path,
			public_key_file, nonce1, proof->val);
	free(nonce1);
	return execute(command);
}




