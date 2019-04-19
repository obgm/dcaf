/*
 * dcaf_crypto_openssl.c -- OpenSSL implementation for DCAF crypto operations
 *
 * Copyright (C) 2017-2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 *
 * Extended by Sara Stadler 2018/2019
 */

#ifdef COAP_DTLS_OPENSSL
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "dcaf/dcaf_crypto.h"
#include "dcaf/dcaf_int.h"

/* The struct algs and the function get_alg() are used to determine
 * which EVP function to use for creating the required cipher suite
 * object.
 */
static struct algs {
  dcaf_key_type alg;
  const EVP_CIPHER *(*get_cipher)(void);
} ciphers[] = {
  { DCAF_AES_128, EVP_aes_128_ccm },
  { DCAF_AES_256, EVP_aes_256_ccm }
};
static inline int
get_alg(dcaf_key_type alg) {
  int idx;
  for (idx = 0; (size_t)idx < sizeof(ciphers)/sizeof(struct algs); idx++) {
    if (ciphers[idx].alg == alg)
      return idx;
  }
  dcaf_log(DCAF_LOG_DEBUG, "cipher not found\n");
  return -1;
}

#define C(Func) if (1 != (Func)) { fprintf(stderr, "oops\n"); }
bool
dcaf_encrypt(const dcaf_crypto_param_t *params,
             const uint8_t *data, size_t data_len,
             const uint8_t *aad, size_t aad_len,
             uint8_t *result, size_t *max_result_len) {
  const EVP_CIPHER *cipher;
  const dcaf_aes_ccm_t *ccm;
  int tmp;
  int result_len = (int)(*max_result_len & INT_MAX);
  int alg;
  assert(params != NULL);

  if (!params || ((alg = get_alg(params->alg)) < 0)) {
    return false;
  }

  /* TODO: set evp_md depending on params->alg */
  ccm = &params->params.aes;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  cipher = ciphers[alg].get_cipher();
                 
  /* EVP_CIPHER_CTX_init(ctx); */
  C(EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL));
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, ccm->l, NULL));
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 15 - ccm->l, NULL));
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, ccm->tag_len, NULL));
  C(EVP_EncryptInit_ex(ctx, NULL, NULL, ccm->key->data, ccm->nonce));
  /* C(EVP_CIPHER_CTX_set_padding(ctx, 0)); */

  C(EVP_EncryptUpdate(ctx, NULL, &result_len, NULL, data_len));
  if (aad && (aad_len > 0)) {
    C(EVP_EncryptUpdate(ctx, NULL, &result_len, aad, aad_len));
  }
  C(EVP_EncryptUpdate(ctx, result, &result_len, data, data_len));
  /* C(EVP_EncryptFinal_ex(ctx, result + result_len, &tmp)); */
  C(EVP_EncryptFinal_ex(ctx, result + result_len, &tmp));
  result_len += tmp;

  /* retrieve the tag */
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, ccm->tag_len,
                        result + result_len));

  *max_result_len = result_len + ccm->tag_len;
  EVP_CIPHER_CTX_free(ctx);
  return true;
}

bool
dcaf_decrypt(const dcaf_crypto_param_t *params,
             const uint8_t *data, size_t data_len,
             const uint8_t *aad, size_t aad_len,
             uint8_t *result, size_t *max_result_len) {
  const EVP_CIPHER *cipher;
  const dcaf_aes_ccm_t *ccm;
  int tmp;
  int len;
  //  int result_len = (int)(*max_result_len & INT_MAX);
  const uint8_t *tag;

  assert(params != NULL);

  if (!params || (params->alg != DCAF_AES_128)) {
    return false;
  }

  ccm = &params->params.aes;

  if (data_len < ccm->tag_len) {
    return false;
  } else {
    tag = data + data_len - ccm->tag_len;
    data_len -= ccm->tag_len;
  }
  
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  /* TODO: set evp_md depending on params->alg */
  cipher = EVP_aes_128_ccm();

  C(EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL));
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 15 - ccm->l, NULL));
  dcaf_debug_hexdump(tag, ccm->tag_len);
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, ccm->tag_len, (void *)tag));
  C(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, ccm->l, NULL));
  /* C(EVP_CIPHER_CTX_set_padding(ctx, 0)); */
  C(EVP_DecryptInit_ex(ctx, NULL, NULL, ccm->key->data, ccm->nonce));

  C(EVP_DecryptUpdate(ctx, NULL, &len, NULL, data_len));
  if (aad && (aad_len > 0)) {
    C(EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len));
  }
  tmp = EVP_DecryptUpdate(ctx, result, &len, data, data_len);
  if (tmp > 0) {
    *max_result_len = len;
  } else {
    *max_result_len = 0;
  }
  EVP_CIPHER_CTX_free(ctx);
  return *max_result_len > 0;
}

bool
dcaf_hmac(const dcaf_crypto_param_t *params,
          const uint8_t *data, size_t data_len,
          uint8_t *result, size_t *max_result_len) {
  unsigned int result_len;
  const EVP_MD *evp_md;

  assert(params);
  assert(data);
  assert(result);
  assert(max_result_len);

  result_len = *max_result_len;
  evp_md = EVP_sha256();
  /* TODO: set evp_md depending on params->alg */
  if (HMAC(evp_md, params->params.key->data,
           params->params.key->length, data, data_len, result, &result_len)) {
    *max_result_len = result_len;
    return true;
  }

  return false;
}
#else /* !COAP_DTLS_OPENSSL */
/* make compilers happy that do not like empty modules */
static inline void
dummy(void) {
}
#endif /* COAP_DTLS_OPENSSL */


/*
 * Encodes readbuf as hex string and stores it in writebuf.
 * source: https://zakird.com/2013/10/13/certificate-parsing-with-openssl
 */
static void hex_encode(unsigned char* readbuf, char *writebuf, size_t len)
{
	for(size_t i=0; i < len; i++) {
		char *l = (char*) (2*i + ((intptr_t) writebuf));
		sprintf(l, "%02x", readbuf[i]);
	}
}

/**
 * Get the fingerprint from a X.509 certificate as hex string.
 * source: https://zakird.com/2013/10/13/certificate-parsing-with-openssl
 */
static char*
get_fingerprint_from_x509(X509* cert) {
	size_t SHA1LEN = 20;
	unsigned char *buf;
	char * strbuf;
	if((buf = dcaf_alloc_type_len(DCAF_VAR_STRING, SHA1LEN)) == NULL){
		return NULL;
	}
	const EVP_MD *digest = EVP_sha1();
	unsigned len;
	int rc = X509_digest(cert, digest,  buf, &len);
	if (rc == 0 || len != SHA1LEN) {
		dcaf_free_type(DCAF_VAR_STRING, buf);
		return NULL;
	}
	if((strbuf = dcaf_alloc_type_len(DCAF_VAR_STRING, 2*SHA1LEN+1)) == NULL){
		dcaf_free_type(DCAF_VAR_STRING, buf);
		return NULL;
	}
	hex_encode(buf, strbuf, SHA1LEN);
	dcaf_free_type(DCAF_VAR_STRING, buf);
	return strbuf;
}


char*
get_fingerprint_from_cert(const uint8_t *asn1_public_cert,
		size_t asn1_length) {
	char *ret;
	const unsigned char *c = (const unsigned char *)asn1_public_cert;
	X509 *cert = d2i_X509(NULL, &c, asn1_length);
	ret = get_fingerprint_from_x509(cert);
	X509_free(cert);
	return ret;
}

bool
export_keying_material(coap_session_t *session, unsigned char *out, size_t out_len, const char *label, size_t label_len,
		const unsigned char *context, size_t context_len){
	SSL *ssl = (SSL *)session->tls;
	if(SSL_export_keying_material(ssl,	out, out_len, label, label_len, context, context_len, 1))
		return true;
	return false;
}
