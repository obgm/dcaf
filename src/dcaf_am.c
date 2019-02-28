/*
 * dcaf_am.c -- libdcaf core
 *
 * Copyright (C) 2015-2018 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2018 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 *
 * Extended by Sara Stadler 2018/2019
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

#include <cn-cbor/cn-cbor.h>

#include "dcaf/utlist.h"

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_am.h"
#include "dcaf/dcaf_abc.h"

#include "dcaf/cose.h"

/* Returns true iff DCAF should be used. */
static bool
is_dcaf(int content_format) {
  return (content_format == -1)
    || (content_format == DCAF_MEDIATYPE_DCAF_CBOR);
}

static cn_cbor *
make_cose_key(const dcaf_key_t *key) {
  cn_cbor *map, *cose_key;

  assert(key);

  if ((map = cn_cbor_map_create(NULL)) == NULL) {
    dcaf_log(DCAF_LOG_DEBUG, "cannot create COSE key: insufficient memory\n");
    return NULL;
  }
  if ((cose_key = cn_cbor_map_create(NULL)) == NULL) {
    dcaf_log(DCAF_LOG_DEBUG, "cannot create COSE key wrapper: insufficient memory\n");
    cn_cbor_free(map);
    return NULL;
  }

  cn_cbor_mapput_int(cose_key, COSE_KEY_KTY,
                     cn_cbor_int_create(COSE_KEY_KTY_SYMMETRIC, NULL),
                     NULL);

  /* set kid or k, depending on type (TODO: may want to set both) */
  /* if (key->type == DCAF_KID) { */
  /*   cn_cbor_mapput_int(map, COSE_KEY_KID, */
  /*                      cn_cbor_data_create(key->data, key->length, NULL), */
  /*                      NULL); */
  /* } else { */
    assert(key->data);
    cn_cbor_mapput_int(cose_key, COSE_KEY_K,
                       cn_cbor_data_create(key->data, key->length, NULL),
                       NULL);
  /* } */

  cn_cbor_mapput_int(map, CWT_COSE_KEY, cose_key, NULL);
  return map;
}

static cn_cbor *
make_ticket_face(dcaf_context_t *dcaf_context, const dcaf_ticket_t *ticket,
                 const dcaf_ticket_request_t *ticket_request) {
  cn_cbor *map = cn_cbor_map_create(NULL);
  cn_cbor *aif, *cose_key;
  cn_cbor *aud = NULL;
  cn_cbor *snc = NULL;
  assert(ticket != NULL);

  aif = dcaf_aif_to_cbor(ticket->aif);
  cose_key = make_cose_key(ticket->key);

  if (!aif || !map || !cose_key) {
    cn_cbor_free(map);
    cn_cbor_free(aif);
    cn_cbor_free(cose_key);
    return NULL;
  }

  if (ticket_request) {
    /* poor man's clone function */
    if (*ticket_request->aud) {
      aud = cn_cbor_string_create(ticket_request->aud, NULL);
    }

    if (ticket_request->snc_length > 0) {
      snc = cn_cbor_data_create(ticket_request->snc,
                                ticket_request->snc_length,
                                NULL);
    }
  }

  if (aud) {
    cn_cbor_mapput_int(map, DCAF_TICKET_AUD, aud, NULL);
  }
  cn_cbor_mapput_int(map, DCAF_TICKET_SCOPE, aif, NULL);
  cn_cbor_mapput_int(map, DCAF_TICKET_SEQ,
                     cn_cbor_int_create(ticket->seq, NULL),
                     NULL);
  cn_cbor_mapput_int(map, DCAF_TICKET_EXPIRES_IN,
                     cn_cbor_int_create(ticket->remaining_time, NULL),
                     NULL);
  cn_cbor_mapput_int(map, DCAF_TICKET_CNF, cose_key, NULL);

  /* Use ticket time stamp as iat field.
   * TODO: representation as ISO-8601? */
  cn_cbor_mapput_int(map, DCAF_TICKET_IAT,
                     cn_cbor_int_create(ticket->ts, NULL),
                     NULL);
  /* Add server nonce if provided in ticket request. */
  if (snc) {
    cn_cbor_mapput_int(map, DCAF_TICKET_SNC, snc, NULL);
  }

  if (DCAF_AM_ENCRYPT_TICKET_FACE && aud) { /* encrypt ticket face*/
    cose_obj_t *cose;
    unsigned char buf[1280];
    size_t buf_len;

    dcaf_key_t *rs_key =
      dcaf_find_key(dcaf_context, NULL, aud->v.bytes, aud->length);

    if (!rs_key) {
      dcaf_log(DCAF_LOG_ERR, "cannot find ticket face encryption key\n");
      cn_cbor_free(map);
      return NULL;
    }

    /* write cbor face to buf, buf_len */
    buf_len = cn_cbor_encoder_write(buf, 0, sizeof(buf), map);
    cn_cbor_free(map);
    map = NULL;

    /* create a valid COSE_Encrypt0 object */
    /* FIXME: select cipher suite according to rs_key->type */
    if (cose_encrypt0(COSE_AES_CCM_16_64_128, rs_key,
                      NULL, 0, buf, &buf_len, &cose) != COSE_OK) {
    /* encrypt failed! */
      dcaf_log(DCAF_LOG_CRIT, "cose_encrypt0: failed\n");
      return NULL;
    }

    assert(cose != NULL);

    /** FIXME: need to have a local copy of the serialized bytes */
    static uint8_t data[256];
    size_t length = sizeof(data);

    if (cose_serialize(cose, COSE_UNTAGGED, data, &length) != COSE_OK) {
      dcaf_log(DCAF_LOG_CRIT, "failed to serialize ticket face\n");
      cose_obj_delete(cose);
      return NULL;
    }

    cose_obj_delete(cose);
    return cn_cbor_data_create(data, length, NULL);
  }
  return map;
}

static cn_cbor *
make_client_info(const dcaf_ticket_t *ticket) {
  cn_cbor *map = cn_cbor_map_create(NULL);
  cn_cbor *cose_key;

  assert(ticket != NULL);

  if (!map) {
    return NULL;
  }

  /* TODO */
  cn_cbor_mapput_int(map, DCAF_TICKET_SEQ,
                     cn_cbor_int_create(ticket->seq, NULL),
                     NULL);
  cose_key = make_cose_key(ticket->key);
  if (cose_key) {
    cn_cbor_mapput_int(map, DCAF_TICKET_CNF, cose_key, NULL);
  }
  return map;
}


/*
 * Encodes a dcaf_nonce_t in a CBOR map. Note that only the
 * value and the length of the nonce are encoded as other fields
 * are not needed for abc.
 */
static cn_cbor *
make_nonce(dcaf_nonce_t *nonce) {
	cn_cbor *map = cn_cbor_map_create(NULL);
    cn_cbor_mapput_int(map, DCAF_NONCE_N,
                       cn_cbor_data_create(nonce->nonce, nonce->nonce_length, NULL),
                       NULL);
    cn_cbor_mapput_int(map, DCAF_NONCE_LEN,
                          cn_cbor_int_create(nonce->nonce_length, NULL),
                          NULL);

	if(!map){
		return NULL;
	}
	return map;
}

static cn_cbor *
make_aif(dcaf_ticket_request_t **treq) {
	cn_cbor *scope;
	scope = cn_cbor_array_create(NULL);
	cn_cbor_array_append(scope,
			cn_cbor_string_create((const char*)(*treq)->aif->perm.resource, NULL),
			NULL);
	cn_cbor_array_append(scope,
			cn_cbor_int_create((*treq)->aif->perm.methods, NULL), NULL);
	if (!scope) {
		return NULL;
	}
	return scope;
}

static cn_cbor *
parse_cbor(const coap_pdu_t *pdu) {
  uint8_t *payload = NULL;
  size_t payload_len = 0;
  cn_cbor *cbor = NULL;

  /* Retrieve payload and parse as CBOR. */
  if (coap_get_data((coap_pdu_t *)pdu, &payload_len, &payload)) {
    cn_cbor_errback errp;
    cbor = cn_cbor_decode(payload, payload_len, &errp);
    if (!cbor) {
      dcaf_log(DCAF_LOG_ERR, "parse error %d at pos %d\n", errp.err, errp.pos);
    }
  }
  else{
	  dcaf_log(DCAF_LOG_ERR, "get pdu data failed\n");
  }
  return cbor;
}

static dcaf_ticket_request_t *
dcaf_new_ticket_request(void) {
  dcaf_ticket_request_t *treq =
    (dcaf_ticket_request_t *)dcaf_alloc_type(DCAF_TICKET_REQUEST);
  if (treq) {
    memset(treq, 0, sizeof(dcaf_ticket_request_t));
  }

  return treq;
}

void
dcaf_delete_ticket_request(dcaf_ticket_request_t *treq) {
  if(treq != NULL){
	  if(treq->aif != NULL){
		  dcaf_free_type(DCAF_AIF, treq->aif);
	  }
	dcaf_free_type(DCAF_TICKET_REQUEST, treq);
  }
}



static unsigned long
next_ticket_seq(void) {
  /* The last issued ticket sequence number. */
  static unsigned long last_seq = 0;
  return ++last_seq;
}

dcaf_result_t
dcaf_create_verifier(dcaf_context_t *ctx, dcaf_ticket_t *ticket) {
  (void)ctx;
  assert(ticket);

  /* FIXME:
   *     - check if we need to generate a new key
   *     - support key generation, e.g. HKDF-based
   */
  if (!ticket->key || !dcaf_key_rnd(ticket->key)) {
    dcaf_delete_key(ticket->key);
    ticket->key = NULL;
    dcaf_log(DCAF_LOG_DEBUG, "dcaf_create_verifier: unsupported key type\n");
    return DCAF_ERROR_UNSUPPORTED_KEY_TYPE;
  }
  /* We have generated a new random key hence we generate a new kid */
  if (dcaf_prng(ticket->key->kid, sizeof(ticket->key->kid))) {
    ticket->key->kid_length = sizeof(ticket->key->kid);
  } else {
    ticket->key->kid_length = 0;
  }

  dcaf_log(DCAF_LOG_DEBUG, "generated key:\n");
  dcaf_debug_hexdump(ticket->key->data, ticket->key->length);
  dcaf_log(DCAF_LOG_DEBUG, "with kid:\n");
  dcaf_debug_hexdump(ticket->key->kid, ticket->key->kid_length);
  return DCAF_OK;
}

//////////////////ABC methods/////////////////
////1. Verifier requests attributes


static dcaf_attribute_request_t *
dcaf_new_attribute_request(void) {
  dcaf_attribute_request_t *areq =
    (dcaf_attribute_request_t *)dcaf_alloc_type(DCAF_ATTRIBUTE_REQUEST);
  if (areq) {
    memset(areq, 0, sizeof(dcaf_attribute_request_t));
  }

  return areq;
}

void
dcaf_delete_attribute_request(dcaf_attribute_request_t *areq) {
  dcaf_free_type(DCAF_NONCE, areq->n);
  dcaf_free_type(DCAF_ATTRIBUTE_REQUEST, areq);
}


dcaf_result_t
dcaf_parse_ticket_request(
                          const coap_pdu_t *request,
                          dcaf_ticket_request_t **result) {
  dcaf_result_t result_code = DCAF_ERROR_BAD_REQUEST;
  dcaf_ticket_request_t *treq = NULL;
  dcaf_aif_t *aif = NULL;
  cn_cbor *body = NULL;
  cn_cbor *aud = NULL;          /* holds the audience field */
  cn_cbor *snc = NULL;          /* holds the server nonce */
  cn_cbor *obj;                 /* holds temporary cbor objects */


  *result = NULL;

  /* Ensure that no Content-Format other than application/dcaf+cbor
   * was requested and that we can parse the message body as CBOR. */
  if (!is_dcaf(coap_get_content_format(request))
      || !(body = parse_cbor(request))) {
    dcaf_log(DCAF_LOG_WARNING, "cannot parse request as application/dcaf+cbor\n");
    return DCAF_ERROR_BAD_REQUEST;
  }

  /* TODO: check if we are addressed AM (iss). If not and we are
   * acting as CAM, the request should be passed on to SAM. */
  obj = cn_cbor_mapget_int(body, DCAF_TICKET_ISS);
  if (obj) {
    if (obj->type != CN_CBOR_TEXT) {
      dcaf_log(DCAF_LOG_WARNING,
               "wrong type for field iss (expected text string)\n");
      goto finish;
    } else {
      dcaf_log(DCAF_LOG_INFO, "iss: \"%.*s\"\n", obj->length, obj->v.str);
    }
  }

  aud = cn_cbor_mapget_int(body, DCAF_TICKET_AUD);
  if (!aud ||
      ((aud->type != CN_CBOR_TEXT) && (aud->type != CN_CBOR_BYTES))) {
    dcaf_log(DCAF_LOG_WARNING, "invalid aud\n");
    goto finish;
  } else {
    /* TODO: check if we know the server denoted by aud */
    dcaf_log(DCAF_LOG_INFO, "aud: \"%.*s\"\n", aud->length, aud->v.str);
  }

  obj = cn_cbor_mapget_int(body, DCAF_TICKET_SCOPE);
  if (obj) {
    if (obj->type == CN_CBOR_TEXT) {
      result_code = dcaf_aif_parse_string(obj, &aif);
    } else {
      result_code = dcaf_aif_parse(obj, &aif);
    }
  } else {
    /* handle default scope */
    const uint8_t scope[] = { 0x82, 0x61, 0x2F, 0x01 }; /* [ "/", 1 ] */
    const size_t scope_length = sizeof(scope);
    cn_cbor *tmp = cn_cbor_decode(scope, scope_length, NULL);
    if (tmp) {
      result_code = dcaf_aif_parse(tmp, &aif);
      cn_cbor_free(tmp);
    }
  }

#if 0
  obj = cn_cbor_mapget_int(body, DCAF_TICKET_CAMT);
  if (obj && (obj->type == CN_CBOR_UINT)) {
    /* TODO: store camt */
  }
#endif
  snc = cn_cbor_mapget_int(body, DCAF_TICKET_SNC);
  if (snc && ((snc->type == CN_CBOR_BYTES) || (snc->type == CN_CBOR_TEXT))) {
    dcaf_log(DCAF_LOG_WARNING, "invalid snc\n");
    goto finish;
  } else if (dcaf_get_log_level() >= DCAF_LOG_INFO) {
    dcaf_log(DCAF_LOG_INFO, "snc:\n");
    dcaf_debug_hexdump(aud->v.str, aud->length);
  }

  if (result_code == DCAF_OK) {
    /* TODO: check if the request contained a kid */

    treq = dcaf_new_ticket_request();
    if (treq) {
      treq->aif = aif;
      if (aud) {
        if (aud->length <= DCAF_MAX_AUDIENCE_SIZE) {
          memset(treq->aud, 0, DCAF_MAX_AUDIENCE_SIZE);
          memcpy(treq->aud, aud->v.str, aud->length);
        } else {
          dcaf_log(DCAF_LOG_WARNING, "aud in ticket request too long\n");
        }
      }

      if (snc) {
        if (snc->length <= DCAF_MAX_NONCE_SIZE) {
          memset(treq->snc, 0, DCAF_MAX_NONCE_SIZE);
          memcpy(treq->snc, snc->v.str, snc->length);
          treq->snc_length = snc->length;
        } else {
          dcaf_log(DCAF_LOG_WARNING, "snc in ticket request too long\n");
        }
      }
    } else {
      /* As we cannot store aif in the ticket structure, we must
       * release its memory manually. */
      dcaf_delete_aif(aif);
      aif = NULL;
    }
  }

 finish:
  cn_cbor_free(body);
  *result = treq;
  return result_code;
}

static dcaf_nonce_t*
parse_nonce(cn_cbor *nonce, cn_cbor *nonce_len, int expected_nonce_len){
	cn_cbor *nonce_n = NULL; /*holds the nonce_n field*/

	//DCAF_MAX_NONCE_SIZE is the only size accepted by the abc methods
		if((int)nonce_len->v.uint != expected_nonce_len){
			dcaf_log(DCAF_LOG_ERR, "parse_nonce: Invalid nonce length\n");
			return NULL;
		}
		nonce_n = cn_cbor_mapget_int(nonce, DCAF_NONCE_N);
		if (!nonce_n || nonce_n->type != CN_CBOR_BYTES) {
			dcaf_log(DCAF_LOG_ERR, "parse_nonce: Cannot parse nonce_n\n");
			return NULL;
		}
		if (nonce_n->length != expected_nonce_len) {
			dcaf_log(DCAF_LOG_ERR, "parse_nonce: Cannot parse nonce_n\n");
			return NULL;
		}
		dcaf_nonce_t* dcaf_nonce = dcaf_new_nonce(nonce_len->v.uint);
		if(!dcaf_nonce){
			dcaf_log(DCAF_LOG_ERR, "parse_nonce: Cannot create dcaf_nonce\n");
			return NULL;
		}
		memset(dcaf_nonce->nonce, 0, expected_nonce_len);
		memcpy(dcaf_nonce->nonce, nonce_n->v.str, nonce_n->length);

		return dcaf_nonce;
}

dcaf_result_t dcaf_parse_attribute_info(
	const coap_pdu_t *request, dcaf_attribute_request_t **result,
	credential_list_st *cred_descriptios) {
	dcaf_result_t result_code = DCAF_ERROR_BAD_REQUEST;
	dcaf_attribute_request_t *areq = NULL;
	dcaf_nonce_t *dcaf_nonce = NULL;
	cn_cbor *body = NULL;
	cn_cbor *nonce = NULL; /* holds the nonce field */
	cn_cbor *nonce_len = NULL; /*holds the nonce_length field*/
	cn_cbor *attributes = NULL; /* holds the attribute field */
	cn_cbor *cred_id = NULL; /*holds the credential id field*/
	int expected_nonce_len;
	*result = NULL;

	/* Ensure that no Content-Format other than application/dcaf+cbor
	 * was requested and that we can parse the message body as CBOR. */
	if (!is_dcaf(coap_get_content_format(request))
			|| !(body = parse_cbor(request))) {
		dcaf_log(DCAF_LOG_ERR,
				"cannot parse request as application/dcaf+cbor\n");
		goto finish;
	}

	cred_id = cn_cbor_mapget_int(body, DCAF_CRED_ID);
	attributes = cn_cbor_mapget_int(body, DCAF_ATTRIBUTES);
	nonce = cn_cbor_mapget_int(body, DCAF_NONCE);
	nonce_len = cn_cbor_mapget_int(nonce, DCAF_NONCE_LEN);
	if (!cred_id || cred_id->type != CN_CBOR_UINT ||
		!attributes || attributes->type != CN_CBOR_UINT ||
		!nonce || nonce->type != CN_CBOR_MAP ||
		!nonce_len || nonce_len->type != CN_CBOR_UINT)
	{
		dcaf_log(DCAF_LOG_ERR, "dcaf_parse_attribute_info: Cannot parse cbor\n");
		goto finish;
	}
	if ((expected_nonce_len = get_required_nonce_length_by_credential(
			cred_descriptios, cred_id->v.uint)) == 0) {
		dcaf_log(DCAF_LOG_ERR,
				"dcaf_parse_attribute_info: Cannot determine expected nonce length\n");
		goto finish;
	}

	dcaf_nonce = parse_nonce(nonce, nonce_len, expected_nonce_len);
	if (!dcaf_nonce)
		goto finish;

	result_code = DCAF_ERROR_INTERNAL_ERROR;

	areq = dcaf_new_attribute_request();
	if(!areq){
		dcaf_log(DCAF_LOG_ERR, "dcaf_parse_attribute_info: Attribute request could not be created\n");
		dcaf_free_type(DCAF_NONCE, dcaf_nonce);
		goto finish;
	}
	areq->cred_id = cred_id->v.uint;
	areq->atributes = attributes->v.uint;
	areq->n = dcaf_nonce;

	result_code = DCAF_OK;

	finish:
	if(body != NULL)
		cn_cbor_free(body);

	*result = areq;
	return result_code;
}

dcaf_result_t
dcaf_parse_disclosure_proof(const coap_pdu_t *cbor_proof,
                          str_st **result){
	int res = DCAF_ERROR_BAD_REQUEST;
	cn_cbor *body = NULL;
	cn_cbor *proof = NULL;
	cn_cbor *proof_len = NULL;

	/* Ensure that no Content-Format other than application/dcaf+cbor
	 * was requested and that we can parse the message body as CBOR. */
	if (!is_dcaf(coap_get_content_format(cbor_proof)) ||
		!(body = parse_cbor(cbor_proof)))
	{
		dcaf_log(DCAF_LOG_ERR,
						"dcaf_extract_proof_string: cannot parse request as application/dcaf+cbor. Not dcaf.\n");
		goto finish;
	}


	proof = cn_cbor_mapget_int(body, DCAF_ATTRIBUTE_PROOF);
	proof_len = cn_cbor_mapget_int(body, DCAF_ATTRIBUTE_PROOF_LEN);

	if (!proof || proof->type != CN_CBOR_TEXT || !proof_len || proof_len->type != CN_CBOR_UINT) {
		dcaf_log(DCAF_LOG_ERR,
						"dcaf_extract_proof_string: Cannot parse attribute proof\n");
		goto finish;
	}

	if((*result = dcaf_new_str(proof_len->v.uint)) == NULL){
		dcaf_log(DCAF_LOG_ERR,"dcaf_extract_proof_string: Memory allocation failure\n");
		res = DCAF_ERROR_INTERNAL_ERROR;
		goto finish;
	}
	memset((*result)->val,0, (*result)->len);
	memcpy((*result)->val, proof->v.str, (*result)->len -1);

	res = DCAF_OK;

	finish:
		if(body != NULL)
			cn_cbor_free(body);
		return res;
}



dcaf_result_t dcaf_set_ticket_request(coap_pdu_t *payload,
		dcaf_ticket_request_t **treq) {
	cn_cbor *body;
	cn_cbor *aud;
	cn_cbor *aif;
	size_t length;
	unsigned char buf[1024];
	int len = strlen(DCAF_AM_TREQ_PATH);
	unsigned char optionbuf[8 + len];

	body = cn_cbor_map_create(NULL);
	aud = cn_cbor_string_create((*treq)->aud, NULL);
	aif = make_aif(treq);

	if (!body || !aud || !aif)
		goto error;

	if (!cn_cbor_mapput_int(body, DCAF_TICKET_SCOPE, aif, NULL)
			|| !cn_cbor_mapput_int(body, DCAF_TICKET_AUD, aud, NULL))
		goto error;

	//write body
	length = cn_cbor_encoder_write(buf, 0, sizeof(buf), body);
	cn_cbor_free(body);

	if (length == 0)
		goto error;

	payload->code = COAP_REQUEST_POST;

	//set options
	coap_add_option(payload, COAP_OPTION_URI_PATH, len,
			(const uint8_t *)DCAF_AM_TREQ_PATH);

	coap_add_option(payload,
	COAP_OPTION_CONTENT_FORMAT,
			coap_encode_var_safe(optionbuf, sizeof(optionbuf),
					DCAF_MEDIATYPE_DCAF_CBOR), optionbuf);

	coap_add_option(payload,
	COAP_OPTION_MAXAGE, coap_encode_var_safe(optionbuf, sizeof(optionbuf), 90),
			optionbuf);

	coap_add_data(payload, length, buf);

	dcaf_log(DCAF_LOG_INFO, "create attribute request \n");
	dcaf_debug_hexdump(buf, length);

	return DCAF_OK;

	error: dcaf_log(DCAF_LOG_ERR,
			"dcaf_set_ticket_request: cannot create payload\n");
	if(body != NULL)
		cn_cbor_free(body);
	return DCAF_ERROR_INTERNAL_ERROR;

}


dcaf_result_t
dcaf_set_attribute_info(coap_pdu_t *response, uint64_t cred_id, uint attr,
	dcaf_nonce_t *n) {
	cn_cbor *body;
	cn_cbor *cred;
	cn_cbor *attributes;
	cn_cbor *nonce;
	size_t length;
	unsigned char buf[1024];
	unsigned char optionbuf[8];

	body = cn_cbor_map_create(NULL);
	cred = cn_cbor_int_create(cred_id, NULL);
	attributes = cn_cbor_int_create(attr, NULL);
	nonce = make_nonce(n);
	if(!body || !cred || !attributes || !nonce)
		goto error;

	if( ! cn_cbor_mapput_int(body, DCAF_CRED_ID, cred, NULL) ||
	! cn_cbor_mapput_int(body, DCAF_ATTRIBUTES, attributes, NULL) ||
	! cn_cbor_mapput_int(body, DCAF_NONCE, nonce, NULL))
		goto error;

	//write body
	length = cn_cbor_encoder_write(buf, 0, sizeof(buf), body);
	cn_cbor_free(body);

	if (length == 0)
		goto error;

	//response code is 204 as the request could be processed
	//successfully but the ticket cannot be provided yet
	response->code = COAP_RESPONSE_CODE(204);

	coap_add_option(response,
	COAP_OPTION_CONTENT_FORMAT,
			coap_encode_var_safe(optionbuf, sizeof(optionbuf),
					DCAF_MEDIATYPE_DCAF_CBOR), optionbuf);

	coap_add_option(response,
	COAP_OPTION_MAXAGE, coap_encode_var_safe(optionbuf, sizeof(optionbuf), 90),
			optionbuf);

	coap_add_data(response, length, buf);

	dcaf_log(DCAF_LOG_INFO, "create attribute request \n");
	dcaf_debug_hexdump(buf, length);

	return DCAF_OK;

	error: dcaf_log(DCAF_LOG_ERR,
			"dcaf_set_attribute_info: cannot create attribute info\n");
	if (body != NULL)
		cn_cbor_free(body);
	response->code = COAP_RESPONSE_CODE(500);
	coap_add_data(response, 14, (unsigned char *) "internal error");
	return DCAF_ERROR_INTERNAL_ERROR;
}


dcaf_result_t
dcaf_set_disclosure_proof(
                      const dcaf_attribute_request_t *attribute_request,
                      coap_pdu_t *payload, const char *credential_file, const char *public_key_file) {
	str_st *proof = NULL;
	cn_cbor *body = NULL;
	cn_cbor *attribute_proof = NULL;
	cn_cbor *proof_len = NULL;
	size_t length;
	unsigned char buf[DCAF_PROOF_MAX_BUF_SIZE];
	memset(buf, 0, DCAF_PROOF_MAX_BUF_SIZE);
	int len = strlen(DCAF_AM_ARES_PATH);
	unsigned char optionbuf[8 + len];


	//generate the proof
	if (generate_proof(credential_file, public_key_file, attribute_request->n,
			attribute_request->atributes, &proof) != DCAF_OK)
		goto error;

	// generate the proof message
	body = cn_cbor_map_create(NULL);
	attribute_proof = cn_cbor_string_create((const char *)proof->val, NULL);
	proof_len = cn_cbor_int_create(proof->len, NULL);
	if (!body || !attribute_proof || !proof_len)
		goto error;

	if(! cn_cbor_mapput_int(body, DCAF_ATTRIBUTE_PROOF, attribute_proof, NULL) ||
	! cn_cbor_mapput_int(body, DCAF_ATTRIBUTE_PROOF_LEN, proof_len, NULL))
		goto error;

	length = cn_cbor_encoder_write(buf, 0, sizeof(buf), body);
	cn_cbor_free(body);
	dcaf_delete_str(proof);

	if (length == 0)
		goto error;

	payload->code = COAP_REQUEST_POST;

	coap_add_option(payload, COAP_OPTION_URI_PATH, len,
			(const uint8_t *) DCAF_AM_ARES_PATH);

	coap_add_option(payload,
	COAP_OPTION_CONTENT_FORMAT,
			coap_encode_var_safe(optionbuf, sizeof(optionbuf),
					DCAF_MEDIATYPE_DCAF_CBOR), optionbuf);

	coap_add_option(payload,
	COAP_OPTION_MAXAGE, coap_encode_var_safe(optionbuf, sizeof(optionbuf), 90),
			optionbuf);

	coap_add_data(payload, length, buf);

	dcaf_log(DCAF_LOG_INFO, "attribute proof is \n");
	dcaf_debug_hexdump(buf, length);


	return DCAF_OK;

	error: dcaf_log(DCAF_LOG_ERR,
			"dcaf_set_attribute_proof: cannot create payload\n");
	if(body != NULL)
		cn_cbor_free(body);
	dcaf_delete_str(proof);
	return DCAF_ERROR_INTERNAL_ERROR;


}

dcaf_result_t
dcaf_set_ticket_grant(const coap_session_t *session,
                      const dcaf_ticket_request_t *ticket_request,
                      coap_pdu_t *response) {
  dcaf_context_t *ctx;
  unsigned char buf[1024];
  unsigned char optionbuf[8];
  size_t length = 0;
  cn_cbor *body = NULL, *ticket_face = NULL, *client_info = NULL;
  dcaf_ticket_t *ticket = NULL;


  ctx = (dcaf_context_t *)coap_get_app_data(session->context);
  if(! ctx)
	  goto error;

  /* Initialize sequence number to 0 and set the real value later to
   * avoid gaps in the sequence number space when ticket creation
   * fails temporarily. */
  ticket = dcaf_new_ticket(DCAF_AES_128, 0,
                           dcaf_gettime(), 3600);
  if (!ticket ||
      (dcaf_create_verifier(ctx, (dcaf_ticket_t *)ticket) != DCAF_OK))
	  goto error;

  ticket->seq = next_ticket_seq();

  /* DCAF_TEST_MODE_ACCEPT accepts all ticket requests automatically. */
  if (DCAF_TEST_MODE_ACCEPT) {
    /* We can move the aif elements from the request to the ticket. */
    assert(ticket->aif == NULL);
    ticket->aif = ticket_request->aif;

    /* Cast needed to get rid of the const qualifier. */
    ((dcaf_ticket_request_t *)ticket_request)->aif = NULL;
  } else {
    /* FIXME: set actual permissions. */
    dcaf_log(DCAF_LOG_WARNING,
             "set_ticket_grant: AIF not set (not implemented)\n");
  }

  /* generate ticket grant depending on media type */
  body = cn_cbor_map_create(NULL);
  ticket_face = make_ticket_face(ctx, ticket, ticket_request);
  client_info = make_client_info(ticket);

  if (!body || !ticket_face || !client_info)
	  goto error;

  if(! cn_cbor_mapput_int(body, DCAF_TICKET_FACE, ticket_face, NULL) ||
  ! cn_cbor_mapput_int(body, DCAF_TICKET_CLIENTINFO, client_info, NULL))
		goto error;


  length = cn_cbor_encoder_write(buf, 0, sizeof(buf), body);
  cn_cbor_free(body);
  dcaf_free_ticket(ticket);

	if (length == 0)
		goto error;

	response->code = COAP_RESPONSE_CODE(200);

	coap_add_option(response,
	COAP_OPTION_CONTENT_FORMAT,
			coap_encode_var_safe(optionbuf, sizeof(optionbuf),
					DCAF_MEDIATYPE_DCAF_CBOR), optionbuf);

	coap_add_option(response,
	COAP_OPTION_MAXAGE, coap_encode_var_safe(optionbuf, sizeof(optionbuf), 90),
			optionbuf);

	coap_add_data(response, length, buf);
	dcaf_log(DCAF_LOG_INFO, "ticket grant is \n");
	dcaf_debug_hexdump(buf, length);

	return DCAF_OK;

	error: dcaf_log(DCAF_LOG_ERR,
			"dcaf_set_ticket_grant: cannot create ticket grant\n");
	if (body != NULL)
		cn_cbor_free(body);
	if(ticket != NULL)
		 dcaf_free_ticket(ticket);
	response->code = COAP_RESPONSE_CODE(500);
	coap_add_data(response, 14, (unsigned char *) "internal error");
	return DCAF_ERROR_INTERNAL_ERROR;
}





