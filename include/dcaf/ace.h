/*
 * ace.h -- specific definitions for ACE coap_dtls profile
 *
 * Copyright (C) 2017 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _ACE_H_
#define _ACE_H_ 1

#define ACE_TOKEN_POP  2

#define ACE_ASINFO_AS            0
#define ACE_ASINFO_NONCE         5

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

enum ace_claim {
  ACE_CLAIM_AUD               = 3,
  ACE_CLAIM_CLIENT_ID         = 8,
  ACE_CLAIM_CLIENT_SECRET     = 9,
  ACE_CLAIM_RESPONSE_TYPE     = 10,
  ACE_CLAIM_REDIRECT_URI      = 11,
  ACE_CLAIM_SCOPE             = 12,
  ACE_CLAIM_STATE             = 13,
  ACE_CLAIM_CODE              = 14,
  ACE_CLAIM_ERROR             = 15,
  ACE_CLAIM_ERROR_DESCRIPTION = 16,
  ACE_CLAIM_ERROR_URI         = 17,
  ACE_CLAIM_GRANT_TYPE        = 18,
  ACE_CLAIM_ACCESS_TOKEN      = 19,
  ACE_CLAIM_TOKEN_TYPE        = 20,
  ACE_CLAIM_EXPIRES_IN        = 21,
  ACE_CLAIM_USERNAME          = 22,
  ACE_CLAIM_PASSWORD          = 23,
  ACE_CLAIM_REFRESH_TOKEN     = 24,
  ACE_CLAIM_CNF               = 25,
  ACE_CLAIM_PROFILE           = 26,
  ACE_CLAIM_RS_CNF            = 31
};

/** Error codes from ACE framework */
enum ace_error_code {
  ACE_ERROR_INVALID_REQUEST        = 0,
  ACE_ERROR_INVALID_CLIENT         = 1,
  ACE_ERROR_INVALID_GRANT          = 2,
  ACE_ERROR_UNAUTHORIZED_CLIENT    = 3,
  ACE_ERROR_UNSUPPORTED_GRANT_TYPE = 4,
  ACE_ERROR_INVALID_SCOPE          = 5,
  ACE_ERROR_UNSUPPORTED_POP_KEY    = 6
};

#endif /* _ACE_H_ */

