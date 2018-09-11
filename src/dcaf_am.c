/*
 * dcaf_am.c -- libdcaf core
 *
 * Copyright (C) 2015-2018 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2018 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <cn-cbor/cn-cbor.h>

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"

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
make_ticket_face(const dcaf_ticket_t *ticket) {
  cn_cbor *map = cn_cbor_map_create(NULL);
  cn_cbor *aif;

  assert(ticket != NULL);

  aif = dcaf_aif_to_cbor(ticket->aif);
  if (!aif || !map) {
    cn_cbor_free(map);
    cn_cbor_free(aif);
    return NULL;
  }

  /* TODO: TS */
  cn_cbor_mapput_int(map, DCAF_TYPE_SAI, aif, NULL);
  /*    cn_cbor_mapput_int(map, DCAF_TYPE_L,
	cn_cbor_int_create(ticket->lifetime, NULL),
	NULL); */
  cn_cbor_mapput_int(map, DCAF_TYPE_G,
		     cn_cbor_int_create(ticket->key->type, NULL),
		     NULL);

  /* encrypt ticket face*/
  {
    cose_obj_t *cose;
    unsigned char buf[1280];
    size_t buf_len;
    static dcaf_key_t rs_key = {
      .length = 11,
    };
    memset(&rs_key, 0, sizeof(dcaf_key_t));
    rs_key.length = 16;
    memcpy(rs_key.data, "RS's secret23456",rs_key.length);

    /* write cbor face to buf, buf_len */
    buf_len = cn_cbor_encoder_write(buf, 0, sizeof(buf), map);
    cn_cbor_free(map);
    map = NULL;

    /* create a valid COSE_Encrypt0 object */
    if (cose_encrypt0(COSE_AES_CCM_16_64_128, &rs_key,
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
  return cbor;
}

/* SAM parses ticket request message from CAM */
dcaf_result_t
dcaf_parse_ticket_request(const coap_session_t *session,
                          const coap_pdu_t *request,
                          dcaf_ticket_t **result) {
  dcaf_result_t result_code = DCAF_ERROR_BAD_REQUEST;
  dcaf_ticket_t *ticket = NULL;
  dcaf_aif_t *aif = NULL;
  cn_cbor *body = NULL;
  cn_cbor *obj;                 /* holds temporary cbor objects */

  assert(result);
  assert(request);
  (void)session;

  *result = NULL;

  /* Ensure that no Content-Format other than application/dcaf+cbor
   * was requested and that we can parse the message body as CBOR. */
  if (!is_dcaf(coap_get_content_format(request))
      || !(body = parse_cbor(request))) {
    dcaf_log(DCAF_LOG_WARNING, "cannot parse request as application/dcaf+cbor\n");
    return DCAF_ERROR_BAD_REQUEST;
  }

  /* TODO: replace parse_token_request */
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

  obj = cn_cbor_mapget_int(body, DCAF_TICKET_AUD);
  if (!obj || (obj->type != CN_CBOR_TEXT)) {
      dcaf_log(DCAF_LOG_WARNING, "invalid aud\n");
      goto finish;
  } else {
    /* TODO: check if we know the server denoted by aud */
    dcaf_log(DCAF_LOG_INFO, "aud: \"%.*s\"\n", obj->length, obj->v.str);
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

  obj = cn_cbor_mapget_int(body, DCAF_TICKET_SNC);
  if (obj && ((obj->type == CN_CBOR_BYTES) || (obj->type == CN_CBOR_TEXT))) {
    /* TODO: store snc */
  }
  
  if (result_code == DCAF_OK) {
#define DCAF_DEFAULT_KID_SIZE 8
    uint8_t kid[DCAF_DEFAULT_KID_SIZE] =
      { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    unsigned long seq = 89;
    dcaf_time_t ts = dcaf_gettime();
    uint8_t key[DCAF_MAX_KEY_SIZE];

    dcaf_prng(key, sizeof(key));
    ticket = dcaf_new_ticket(kid, sizeof(kid),
                             DCAF_AES_128,
                             key, sizeof(key),
                             seq, ts, DCAF_DEFAULT_LIFETIME);
    if (ticket) {
      ticket->aif = aif;
    } else {
      /* As we cannot store aif in the ticket structure, we must
       * release its memory manually. */
      dcaf_delete_aif(aif);
      aif = NULL;
    }
  }

 finish:
  cn_cbor_free(body);
  *result = ticket;
  return result_code;
}


#define MAJOR_TYPE_BYTE_STRING (2 << 5)


void
dcaf_set_ticket_grant(const coap_session_t *session,
                      const dcaf_ticket_t *ticket,
                      coap_pdu_t *response) {
  dcaf_context_t *ctx;
  unsigned char buf[128];
  size_t length = 0;
  assert(ticket);
  assert(response);

  ctx = (dcaf_context_t *)coap_get_app_data(session->context);
  assert(ctx);

  if (dcaf_create_verifier(ctx, (dcaf_ticket_t *)ticket) != DCAF_OK) {
    dcaf_log(DCAF_LOG_CRIT, "cannot create verifier\n");
    response->code = COAP_RESPONSE_CODE(500);
    coap_add_data(response, 14, (unsigned char *)"internal error");
    return;
  }

  /* generate ticket grant depending on media type */
  buf[0] = 0xa2; /* map(2) */
  buf[1] = DCAF_TYPE_F; /* unsigned int */
  cn_cbor *face = make_ticket_face(ticket);

  length = cn_cbor_encoder_write(buf, 2, sizeof(buf), face);
  /* TODO: create verifier over buf and append to map */
  
  buf[length + 2] = DCAF_TYPE_V; /* unsigned int */
  
#if 0
  switch (ticket->key->type) {
  case DCAF_KEY_HMAC_SHA256:
    /* fall through */
  case DCAF_KEY_HMAC_SHA384:
    /* fall through */
  case DCAF_KEY_HMAC_SHA512: {
    const size_t face_length = length;
    size_t len = sizeof(buf) - length;
    dcaf_crypto_param_t params = {
      .alg = DCAF_HS256,    /* TODO: support for additional types */
      .params.key = ticket->key
    };
    length += 3;
    if (dcaf_create_verifier(&params, buf + 3, face_length,
			     buf + length, &len) == DCAF_OK) {
      length += len;
    }
    break;
  }
  case DCAF_AES_CCM_16_64_128: {
    /* TODO */
    break;
  }
  default:
    ;
  }
#endif
  cn_cbor_free(face);
  
  if (length > 0) {  /* we have a response */
    unsigned char optionbuf[8];

    response->code = COAP_RESPONSE_CODE(201);
    coap_add_option(response,
                    COAP_OPTION_CONTENT_FORMAT,
                    coap_encode_var_safe(optionbuf, sizeof(optionbuf),
                                         DCAF_MEDIATYPE_DCAF_CBOR),
                    optionbuf);

    coap_add_option(response,
                    COAP_OPTION_MAXAGE,
                    coap_encode_var_safe(optionbuf, sizeof(optionbuf), 90),
                    optionbuf);

    coap_add_data(response, length, buf);
    dcaf_log(DCAF_LOG_INFO, "ticket grant is \n");
    dcaf_debug_hexdump(buf, length);
  } else { /* something went wrong, prepare error response */
    dcaf_log(DCAF_LOG_CRIT, "cannot create ticket grant\n");
    response->code = COAP_RESPONSE_CODE(500);
    coap_add_data(response, 14, (unsigned char *)"internal error");
  }
}

dcaf_result_t
dcaf_create_verifier(dcaf_context_t *ctx, dcaf_ticket_t *ticket) {
  (void)ctx;
  assert(ticket);

  /* FIXME:
   *     - check if we need to generate a new key
   *     - support key generation, e.g. HKDF-based
   */
  if (ticket->key == NULL) {
    ticket->key = dcaf_new_key(DCAF_AES_128);
    if (!ticket->key || !dcaf_key_rnd(ticket->key)) {
      dcaf_delete_key(ticket->key);
      ticket->key = NULL;
      return DCAF_ERROR_UNSUPPORTED_KEY_TYPE;
    }
    dcaf_log(DCAF_LOG_DEBUG, "generated key:\n");
    dcaf_debug_hexdump(ticket->key->data, ticket->key->length);
    return DCAF_OK;
  }
#if 0
  size_t len;
  if (!(out_length && (*out_length > 2))) {
    return DCAF_ERROR_BUFFER_TOO_SMALL;
  }

  len = *out_length - 2;
  if (dcaf_hmac(params, face, face_length, output + 2, &len)) {
    output[0] = MAJOR_TYPE_BYTE_STRING | 25;
    output[1] = len;          /* TODO: handle len < 24 or len > 255 */
    *out_length = len + 2;
    return DCAF_OK;
  }
#endif

  dcaf_log(DCAF_LOG_DEBUG, "dcaf_create_verifier: key should have been NULL\n");
  return DCAF_ERROR_INTERNAL_ERROR;
}

