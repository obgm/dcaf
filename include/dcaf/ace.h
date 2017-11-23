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

#define ACE_CLAIM_ISS            1
#define ACE_CLAIM_SUB            2
#define ACE_CLAIM_AUD            3
#define ACE_CLAIM_EXP            4
#define ACE_CLAIM_NBF            5
#define ACE_CLAIM_IAT            6
#define ACE_CLAIM_CTI            7
#define ACE_CLAIM_CLIENT_ID      8
#define ACE_CLAIM_CLIENT_SECRET  9

#define ACE_CLAIM_SCOPE         12
#define ACE_CLAIM_ERROR         15
#define ACE_CLAIM_ERROR_DESC    16
#define ACE_CLAIM_ERROR_URI     17

#define ACE_CLAIM_ACCESS_TOKEN  19
#define ACE_CLAIM_TOKEN_TYPE    20
#define ACE_CLAIM_EXPIRES_IN    21

#define ACE_CLAIM_CNF           25
#define ACE_CLAIM_PROFILE       26

#define ACE_ASINFO_AS            0
#define ACE_ASINFO_NONCE         5

#define ACE_PROFILE_COAP_DTLS  3

#endif /* _ACE_H_ */

