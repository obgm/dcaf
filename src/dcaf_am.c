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

#include "dcaf/utlist.h"

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_am.h"

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

/* Create a CBOR representation of AIF using cn-cbor. */
static cn_cbor *
aif_to_cbor(const dcaf_aif_t *aif) {
  cn_cbor *result;
  const dcaf_aif_t *tmp;

  if (!aif || !(result = cn_cbor_array_create(NULL))) {
    return NULL;
  }

  LL_FOREACH(aif, tmp) {
    cn_cbor *resource, *methods;
    resource = cn_cbor_string_create((const char *)tmp->perm.resource,
                                       NULL);
    methods =  cn_cbor_int_create(tmp->perm.methods, NULL);
    if (!resource || !methods) {
      dcaf_log(DCAF_LOG_DEBUG, "out of memory when creating AIF\n");
      cn_cbor_free(resource);
      cn_cbor_free(methods);
      break;
    }

    cn_cbor_array_append(result, resource, NULL);
    cn_cbor_array_append(result, methods, NULL);
  }

  if (result->length == 0) {
    /* we ran out of memory during AIF creation, so just give up */
    cn_cbor_free(result);
    return NULL;
  } else {
    return result;
  }
}


static cn_cbor *
make_ticket_face(dcaf_context_t *dcaf_context, const dcaf_ticket_t *ticket,
                 const dcaf_ticket_request_t *ticket_request) {
  cn_cbor *map = cn_cbor_map_create(NULL);
  cn_cbor *aif, *cose_key;
  cn_cbor *aud = NULL;
  cn_cbor *snc = NULL;
  assert(ticket != NULL);

  aif = aif_to_cbor(ticket->aif);
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
    } else {
      dcaf_log(DCAF_LOG_ERR, "encrypt with rs_key: '%.*s' for aud '%.*s'\n",
               (int)rs_key->length, rs_key->data,
               (int)aud->length, aud->v.bytes);
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

static bool
add_client_info(cn_cbor *map, const dcaf_ticket_t *ticket, int flags) {
  bool ok = false;
  cn_cbor *cose_key;

  assert(ticket != NULL);

  if (map) {
    dcaf_time_t now = dcaf_gettime();

    /* TODO */
    cn_cbor_mapput_int(map, DCAF_CINFO_IAT,
                       cn_cbor_int_create(now, NULL),
                       NULL);

    cn_cbor_mapput_int(map, DCAF_CINFO_SEQ,
                       cn_cbor_int_create(ticket->seq, NULL),
                       NULL);
    cose_key = make_cose_key(ticket->key);
    if (cose_key) {
      cn_cbor_mapput_int(map, DCAF_CINFO_CNF, cose_key, NULL);
      ok = true;
    }

    if (flags & AM_INCLUDE_PROFILE) {
      cn_cbor_mapput_int(map, ACE_MSG_PROFILE,
                         cn_cbor_int_create(ACE_PROFILE_DTLS, NULL),
                         NULL);
    }
  }
  return ok;
}

static abor_decoder_t *
get_cbor(const coap_pdu_t *pdu) {
  uint8_t *payload = NULL;
  size_t payload_len = 0;
  abor_decoder_t *cbor = NULL;

  /* Retrieve payload and create CBOR parser. */
  if (coap_get_data((coap_pdu_t *)pdu, &payload_len, &payload)) {
    cbor = abor_decode_start(payload, payload_len);
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
  dcaf_delete_aif(treq->aif);
  dcaf_free_type(DCAF_TICKET_REQUEST, treq);
}

static dcaf_ticket_request_t *
create_default_ticket_request(void) {
  dcaf_ticket_request_t *treq = dcaf_new_ticket_request();
  dcaf_aif_t *aif = dcaf_new_aif();

  if ((treq != NULL) && (aif != NULL)) {
    const char dcaf_default_audience[] = "coaps://dcaf-temp";
    const char dcaf_default_resource[] = "restricted";
    uint32_t dcaf_default_methods = COAP_REQUEST_GET;

    assert(sizeof(dcaf_default_audience) <= DCAF_MAX_AUDIENCE_SIZE + 1);
    assert(sizeof(dcaf_default_resource) <= DCAF_MAX_RESOURCE_LEN + 1);
    memcpy(treq->aud, dcaf_default_audience, sizeof(dcaf_default_audience));

    memcpy(aif->perm.resource, dcaf_default_resource, sizeof(dcaf_default_resource));
    aif->perm.resource_len = sizeof(dcaf_default_resource) - 1;
    aif->perm.methods = dcaf_default_methods;

    treq->aif = aif;
  } else {
    dcaf_delete_ticket_request(treq);
    dcaf_delete_aif(aif);       /* aif is no part of treq here */
    treq = NULL;
  }
  return treq;
}

/* SAM parses ticket request message from CAM */
dcaf_result_t
dcaf_parse_ticket_request(const coap_session_t *session,
                          const coap_pdu_t *request,
                          dcaf_ticket_request_t **result) {
  dcaf_result_t result_code = DCAF_ERROR_BAD_REQUEST;
  dcaf_ticket_request_t *treq = NULL;
  dcaf_aif_t *aif = NULL;
  abor_decoder_t *abd = NULL;
  abor_decoder_t *aud = NULL;   /* holds the audience field */
  abor_decoder_t *snc = NULL;   /* holds the server nonce */
  abor_decoder_t *obj;          /* holds temporary cbor objects */

  assert(result);
  assert(request);
  (void)session;

  *result = NULL;

  /* Ensure that no Content-Format other than application/dcaf+cbor
   * was requested and that we can parse the message body as CBOR. */
  if (!is_dcaf(coap_get_content_format(request))) {
    dcaf_log(DCAF_LOG_WARNING, "cannot parse request as application/dcaf+cbor\n");
    return DCAF_ERROR_BAD_REQUEST;
  }
  abd = get_cbor(request);

  /* An empty ticket request is responded to with a default
   * configuration for this client. */
  if (!abd) {
    *result = create_default_ticket_request();
    return *result ? DCAF_OK : DCAF_ERROR_OUT_OF_MEMORY;
  }

  /* TODO: check if we are addressed AM (iss). If not and we are
   * acting as CAM, the request should be passed on to SAM. */
  obj = abor_mapget_int(abd, DCAF_REQ_SAM);
  if (obj && abor_check_type(obj, ABOR_TSTR)) {
    dcaf_log(DCAF_LOG_INFO, "iss: \"%.*s\"\n", (int)abor_get_sequence_length(obj), abor_get_text(obj));
  } else {
    dcaf_log(DCAF_LOG_WARNING, "field iss missing or invalid\n");
    goto finish;
  }
  abor_decode_finish(obj);
  obj = NULL;

  treq = dcaf_new_ticket_request();
  if (!treq) {
    result_code = DCAF_ERROR_OUT_OF_MEMORY;
    goto finish;
  }

  aud = abor_mapget_int(abd, DCAF_REQ_AUD);
  if (!aud) {
    dcaf_log(DCAF_LOG_WARNING, "field aud is missing\n");
    goto finish;
  } else {
    abor_type mt = abor_get_type(aud);
    size_t aud_length;

    if ((mt != ABOR_TSTR) && (mt != ABOR_BSTR)) {
      dcaf_log(DCAF_LOG_WARNING, "invalid field aud\n");
      goto finish;
    }
    /* TODO: check if we know the server denoted by aud */
    dcaf_log(DCAF_LOG_INFO, "aud: \"%.*s\"\n", (int)abor_get_sequence_length(aud), abor_get_text(aud));

    aud_length = abor_get_sequence_length(aud);
    if (aud_length <= DCAF_MAX_AUDIENCE_SIZE) {
      memset(treq->aud, 0, sizeof(treq->aud));
      memcpy(treq->aud, abor_get_bytes(aud), aud_length);
    } else {
      dcaf_log(DCAF_LOG_WARNING, "aud in ticket request too long\n");
    }
  }
  /* aud is released at the end */

  obj = abor_mapget_int(abd, DCAF_REQ_SCOPE);
  if (!obj) {
    /* handle default scope */
    static const uint8_t scope[] = { 0x82, 0x61, 0x2F, 0x01 }; /* [ "/", 1 ] */
    obj = abor_decode_start(scope, sizeof(scope));
  }

  if (obj) { /* may fail if memory allocation failed for default scope */
    if (abor_check_type(obj, ABOR_TSTR)) {
      result_code = dcaf_aif_parse_string(obj, &aif);
    } else {
      result_code = dcaf_aif_parse(obj, &aif);
    }
    treq->aif = aif;
  }
  abor_decode_finish(obj);
  obj = NULL;

  /* If the request contained an ace_profile parameter, the response
   * must specify the profile to use. */
  obj = abor_mapget_int(abd, ACE_MSG_PROFILE);
  if (obj) {
    treq->flags |= AM_INCLUDE_PROFILE;
    abor_decode_finish(obj);
    obj = NULL;
  }

  snc = abor_mapget_int(abd, DCAF_REQ_SNC);
  if (snc) {
    abor_type mt = abor_get_type(snc);
    size_t snc_length;
    if ((mt == ABOR_TSTR) || (mt == ABOR_BSTR)) {
      if (dcaf_get_log_level() >= DCAF_LOG_INFO) {
        dcaf_log(DCAF_LOG_INFO, "snc:\n");
        dcaf_debug_hexdump(abor_get_bytes(snc), abor_get_sequence_length(snc));
      }
    } else {
      dcaf_log(DCAF_LOG_WARNING, "invalid field snc\n");
      goto finish;
    }

    snc_length = abor_get_sequence_length(snc);
    if (snc_length <= DCAF_MAX_NONCE_SIZE) {
      memset(treq->snc, 0, DCAF_MAX_NONCE_SIZE);
      memcpy(treq->snc, abor_get_bytes(snc), snc_length);
      treq->snc_length = snc_length;
    } else {
      dcaf_log(DCAF_LOG_WARNING, "snc in ticket request too long\n");
    }
  }
  /* snc is released at the end */

 finish:
  abor_decode_finish(aud);
  abor_decode_finish(snc);
  abor_decode_finish(obj);      /* release any obj still remaining */
  abor_decode_finish(abd);

  if (result_code == DCAF_OK) {
    *result = treq;
  } else {
    dcaf_delete_ticket_request(treq);
  }
  return result_code;
}

static unsigned long
next_ticket_seq(void) {
  /* The last issued ticket sequence number. */
  static unsigned long last_seq = 0;
  return ++last_seq;
}

void
dcaf_set_ticket_grant(const coap_session_t *session,
                      const dcaf_ticket_request_t *ticket_request,
                      coap_pdu_t *response) {
  dcaf_context_t *ctx;
  unsigned char buf[1024];
  size_t length = 0;
  cn_cbor *body, *ticket_face;
  dcaf_ticket_t *ticket;

  assert(ticket_request);
  assert(response);

  ctx = (dcaf_context_t *)coap_get_app_data(session->context);
  assert(ctx);

  /* Initialize sequence number to 0 and set the real value later to
   * avoid gaps in the sequence number space when ticket creation
   * fails temporarily. */
  ticket = dcaf_new_ticket(DCAF_AES_128, 0,
                           dcaf_gettime(), 3600);
  if (!ticket ||
      (dcaf_create_verifier(ctx, (dcaf_ticket_t *)ticket) != DCAF_OK)) {
    dcaf_log(DCAF_LOG_CRIT, "cannot create ticket\n");
    response->code = COAP_RESPONSE_CODE(500);
    coap_add_data(response, 14, (unsigned char *)"internal error");
    return;
  }

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
  if (!body || !ticket_face) {
    cn_cbor_free(ticket_face);
    goto error;
  }

  cn_cbor_mapput_int(body, DCAF_CINFO_TICKET_FACE, ticket_face, NULL);
  if (!add_client_info(body, ticket, ticket_request->flags)) {
    goto error;
  }

  length = cn_cbor_encoder_write(buf, 0, sizeof(buf), body);
  cn_cbor_free(body);

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
    return;
  }

 error:
  cn_cbor_free(body);
  dcaf_log(DCAF_LOG_CRIT, "cannot create ticket grant\n");
  response->code = COAP_RESPONSE_CODE(500);
  coap_add_data(response, 14, (unsigned char *)"internal error");
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
