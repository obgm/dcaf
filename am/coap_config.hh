#ifndef _DCAF_COAP_CONFIG_HH
#define _DCAF_COAP_CONFIG_HH 1

#include <coap3/coap.h>
#include "config_parser.hh"

namespace am_config {

bool am_setup_pki(coap_context_t *ctx, const parser::HostConfig &config, coap_dtls_pki_t &dtls_pki);

} /* namespace am_config */

#endif /* _DCAF_COAP_CONFIG_HH */
