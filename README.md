# DCAF ABC extensions #
This branch provides an extension to the DCAF protocol, where the authentication and authorization of CAM is carried out by means of attribute-based credentials.
For this the implementation uses the [Gabi](https://github.com/mhe/gabi) cryptographic library and an extended version of the of [mhe/irmatool](https://github.com/mhe/irmatool).
Note that the implementation was provided as a Proof of Concept and is not ready for real-world applications.

# DCAF #
dcaf: Authenticated Authorization for the Internet of Things

Copyright (c) 2015—2019 by Olaf Bergmann <bergmann@tzi.org>
              2015—2019 by Stefanie Gerdes <gerdes@tzi.org>

ABOUT DCAF
==========

The Delegated CoAP Authentication and Authorization Framework (DCAF)
defines an architecture and a protocol for delegating client
authentication and authorization in a constrained environment for
establishing a secure communication context between
resource-constrained nodes, utilizing Datagram Transport Layer
Security (DTLS) or CBOR message syntax (COSE). 

The protocol transfers authorization information and shared secrets
for symmetric cryptography between entities in a constrained
network. A resource-constrained node can use the protocol to delegate
authentication of communication peers and management of authorization
information to a trusted host with less severe limitations regarding
processing power and memory.

More information on DCAF is available at
https://tools.ietf.org/html/draft-gerdes-ace-dcaf-authorize

PACKAGE CONTENTS
================

This library contains a protocol parser and basic handling functions
for integration with libcoap.

LICENSE INFORMATION
===================

This library is published as open-source software without any warranty
of any kind. Use is permitted under the terms of the MIT license.
Please refer to LICENSE for further details.

