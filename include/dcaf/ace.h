/*
 * ace.h -- specific definitions for ACE coap_dtls profile
 *
 * Copyright (C) 2017-2020 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _ACE_H_
#define _ACE_H_ 1

/** OAuth grant types as defined in draft-ietf-ace-oauth-authz */
enum ace_grant_type {
  ACE_GRANT_PASSWORD = 0,
  ACE_GRANT_AUTHORIZATION_CODE = 1,
  ACE_GRANT_CLIENT_CREDENTIALS = 2,
  ACE_GRANT_REFRESH_TOKEN = 3
};

/** Values for the profile parameter */
enum ace_profile {
  ACE_PROFILE_DTLS = 1,         /* draft-ietf-ace-dtls-authorize */
  ACE_PROFILE_OSCORE = 2        /* draft-ietf-ace-oscore-profile */
};

#ifdef CONFIG_ACE_REQUEST_PROFILE
#define ACE_REQUEST_PROFILE CONFIG_ACE_REQUEST_PROFILE
#else  /* !CONFIG_ACE_REQUEST_PROFILE */
#define ACE_REQUEST_PROFILE 0
#endif /* !CONFIG_ACE_REQUEST_PROFILE */

/* CBOR mappings for token request and response fields according to
 * draft-ietf-ace-oauth-authz-33, draft-ietf-ace-oauth-params-13
 */

enum ace_msg {
  ACE_MSG_ACCESS_TOKEN      = 1,
  ACE_MSG_EXPIRES_IN        = 2,
  ACE_MSG_AUDIENCE          = 3,
  ACE_MSG_CNF               = 8,
  ACE_MSG_SCOPE             = 9,
  ACE_MSG_CLIENT_ID         = 24,
  ACE_MSG_CLIENT_SECRET     = 25,
  ACE_MSG_RESPONSE_TYPE     = 26,
  ACE_MSG_REDIRECT_URI      = 27,
  ACE_MSG_STATE             = 28,
  ACE_MSG_CODE              = 29,
  ACE_MSG_ERROR             = 30,
  ACE_MSG_ERROR_DESCRIPTION = 31,
  ACE_MSG_ERROR_URI         = 32,
  ACE_MSG_GRANT_TYPE        = 33,
  ACE_MSG_TOKEN_TYPE        = 34,
  ACE_MSG_USERNAME          = 35,
  ACE_MSG_PASSWORD          = 36,
  ACE_MSG_REFRESH_TOKEN     = 37,
  ACE_MSG_PROFILE           = 38,
  ACE_MSG_CNONCE            = 39,
  ACE_MSG_RS_CNF            = 41,
};

/* CBOR values for ACE AS Request Creation Hints according to
 * draft-ietf-ace-oauth-authz-33:
 */
enum ace_req_creation_hints {
  ACE_REQ_HINT_AS     = 1,
  ACE_REQ_HINT_KID    = 2,
  ACE_REQ_HINT_AUD    = 5,
  ACE_REQ_HINT_SCOPE  = 9,
  ACE_REQ_HINT_CNONCE = 39
};

/** Error codes from ACE framework */
enum ace_error_code {
  ACE_ERROR_INVALID_REQUEST        = 1,
  ACE_ERROR_INVALID_CLIENT         = 2,
  ACE_ERROR_INVALID_GRANT          = 3,
  ACE_ERROR_UNAUTHORIZED_CLIENT    = 4,
  ACE_ERROR_UNSUPPORTED_GRANT_TYPE = 5,
  ACE_ERROR_INVALID_SCOPE          = 6,
  ACE_ERROR_UNSUPPORTED_POP_KEY    = 7,
  ACE_ERROR_INCOMPATIBLE_PROFILES  = 8,
};

#endif /* _ACE_H_ */

