#ifndef CWT_H
#define CWT_H 1

/*
   CBOR values for CWT claims according to RFC 8392:

   +---------+------------------------+--------------------------+
   | Claim   | CBOR encoded claim key | CBOR major type of value |
   |---------+------------------------+--------------------------|
   | iss     | 1                      | 3                        |
   | sub     | 2                      | 3                        |
   | aud     | 3                      | 3                        |
   | exp     | 4                      | 6 tag value 1            |
   | nbf     | 5                      | 6 tag value 1            |
   | iat     | 6                      | 6 tag value 1            |
   | cti     | 7                      | 2                        |
   +---------+------------------------+--------------------------+
*/

enum cwt_claim {
  CWT_CLAIM_ISS = 1,
  CWT_CLAIM_SUB = 2,
  CWT_CLAIM_AUD = 3,
  CWT_CLAIM_EXP = 4,
  CWT_CLAIM_NBF = 5,
  CWT_CLAIM_IAT = 6,
  CWT_CLAIM_CTI = 7,
  CWT_CLAIM_CNF = 8,
  /* additional claim keys from RFC 9200: */
  CWT_CLAIM_SCOPE       = 9,
  CWT_CLAIM_ACE_PROFILE = 38,
  CWT_CLAIM_CNONCE      = 39,
  CWT_CLAIM_EXI         = 40,
  CWT_CLAIM_RS_CNF      = 41,
};

enum cwt_cnf {
  CWT_CNF_COSE_KEY            = 1,
  CWT_CNF_ENCRYPTED_COSE_KEY  = 2,
  CWT_CNF_KID                 = 3,
};

/* CBOR tag for CWT structure */
enum cwt_cbor_tag {
  CWT_CBOR_TAG = 61
};

#endif /* CWT_H */
