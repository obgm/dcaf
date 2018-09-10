/*
 * ace.c -- libace core
 *
 * Copyright (C) 2015-2018 Olaf Bergmann <bergmann@tzi.org>
 *               2015-2018 Stefanie Gerdes <gerdes@tzi.org>
 *
 * This file is part of the ACE library libace. Please see README
 * for terms of use.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <cn-cbor/cn-cbor.h>

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"

#include "dcaf/ace.h"

/**
 * Parses @p data into @p result. This function returns true on
 * success, or false on error.
 *
 * @param data      The token request to parse.
 * @param data_len  The actual size of @p data.
 * @param result    The result object if true.
 *
 * @return false on parse error, true otherwise.
 */
static bool
parse_token_request(const uint8_t *data,
                    size_t data_len,
                    dcaf_authz_t *result) {
  cn_cbor_errback errp;
  const cn_cbor *token_request;
  const cn_cbor *cnf, *k, *aud, *scope;

  assert(data);
  assert(result);

  token_request = cn_cbor_decode(data, data_len, &errp);

  if (!token_request) {
    log_parse_error(errp);
    result->code = DCAF_ERROR_BAD_REQUEST;
    return false;
  }

  /* check contents of cnf item, if present */
  cnf = cn_cbor_mapget_int(token_request, CWT_CLAIM_CNF);
  if (cnf) {
    if (cnf->type != CN_CBOR_MAP) {
      dcaf_log(DCAF_LOG_DEBUG, "invalid cnf value in token request\n");
      result->code = DCAF_ERROR_BAD_REQUEST;
      goto finish;
    }

    k = cn_cbor_mapget_int(cnf, CWT_CNF_KID);
    if (k) {
      /* TODO: check if kid is allowed for this session */
      result->code = DCAF_ERROR_UNSUPPORTED_KEY_TYPE;
    } else {
      if ((k = get_cose_key(cnf)) != NULL) {
        /* TODO: check if kty is ECC */
        cn_cbor *kty = cn_cbor_mapget_int(k, COSE_KEY_KTY);
        if (kty && kty->v.sint == COSE_KEY_KTY_SYMMETRIC) {
          /* token requests must not contain a symmetric key */
          dcaf_log(DCAF_LOG_DEBUG, "kty=symmetric not allowed in token request\n");
          result->code = DCAF_ERROR_BAD_REQUEST;
        } else {
          /* TODO: ECC key */
          result->code = DCAF_ERROR_UNSUPPORTED_KEY_TYPE;
        }
      }
    }
  }

  /* We need an aud parameter, otherwise it is not clear
   * which server is to be accessed. */
  aud = cn_cbor_mapget_int(token_request, ACE_CLAIM_AUD);
  if (aud) {
    /* TODO: check if we know that server, and if the request
     * contained a kid parameter, this server has an active session
     * that uses a key that is represented by kid.
     */
  }

  /* We need a scope, otherwise we would not know what is
   * requested. */
  scope = cn_cbor_mapget_int(token_request, ACE_CLAIM_SCOPE);
  if (scope) {
    /* TODO: parse AIF */
    if (dcaf_aif_parse(scope, &result->aif))
      result->code = DCAF_OK;
  }

 finish:
  cn_cbor_free((cn_cbor *)token_request);
  return true;
}
