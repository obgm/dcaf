#include <filesystem>
#include <string>

#include "dcaf/dcaf.h"

#include "coap_config.hh"

namespace am_config {

static void
update_pki_key(coap_dtls_key_t &dtls_key, const std::string &key_name,
               const std::string &cert_name, const std::string &ca_name) {
  dtls_key.key_type = COAP_PKI_KEY_PEM;
  dtls_key.key.pem.public_cert = cert_name.c_str();
  dtls_key.key.pem.private_key = key_name.empty() ? cert_name.c_str() : key_name.c_str();
  dtls_key.key.pem.ca_file = ca_name.c_str();
}

template <typename T, typename Container>
static bool check_item(const T &item, const Container &cont, const char *desc) {
  if (item == cont.end()) {
    dcaf_log(DCAF_LOG_ERR, "%s not specified\n", desc);
    return false;
  }
  if (!std::filesystem::is_regular_file(item->second)) {
    dcaf_log(DCAF_LOG_ERR, "%s '%s' not readable\n", desc, item->second.c_str());
    return false;
  }
  return true;
}

bool
am_setup_pki(coap_context_t *ctx, const parser::HostConfig &config, coap_dtls_pki_t &dtls_pki) {
  std::error_code err;
  const auto trust_roots{config.find("trust_roots")};
  const auto ca_file{config.find("ca_file")};
  
  /* set root CA if defined. */
  if (ctx && (trust_roots != config.end())) {
    if (std::filesystem::is_directory(trust_roots->second)) {
      coap_context_set_pki_root_cas(ctx, NULL, trust_roots->second.c_str());
    } else if (std::filesystem::is_regular_file(trust_roots->second)) {
      coap_context_set_pki_root_cas(ctx, trust_roots->second.c_str(), NULL);
    } else {
      dcaf_log(DCAF_LOG_WARNING, "Cannot set trust anchors: %s\n", trust_roots->second.c_str());
    }
  }

  memset (&dtls_pki, 0, sizeof(dtls_pki));
  dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
  if ((ca_file != config.end()) || (trust_roots != config.end())) {
    /* see 'man coap_encryption' for parameter values
     */
    if (trust_roots == config.end()) {
      dtls_pki.check_common_ca = 1;
    }
    // dtls_pki.allow_self_signed       = 1;
    // dtls_pki.allow_expired_certs     = 1;
    dtls_pki.cert_chain_validation   = 1;
    dtls_pki.cert_chain_verify_depth = 2;
    dtls_pki.check_cert_revocation   = 1;
    dtls_pki.allow_no_crl            = 1;
    dtls_pki.allow_expired_crl       = 1;
  }

  const auto pem_file{config.find("pem_file")};
  const auto key_file{config.find("key_file")};
  bool ok = true;

  ok = check_item(pem_file, config, "pem_file") && ok;
  ok = check_item(key_file, config, "key_file") && ok;

  update_pki_key(dtls_pki.pki_key, key_file->second, pem_file->second, ca_file->second);
  return ok;
}

} /* namespace am_config */
