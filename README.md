# DCAF #
dcaf: Authenticated Authorization for the Internet of Things

Copyright (c) 2015—2019 by Olaf Bergmann <bergmann@tzi.org>
              2015—2019 by Stefanie Gerdes <gerdes@tzi.org>

dcaf abc extensions:

Copyright (c) 2018—2019 by Sara Stadler <stadlers@tzi.org>

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

## DCAF ABC extensions

This branch provides an extension to the DCAF protocol, where the
authentication and authorization of CAM is carried out by means of
attribute-based credentials (ABCs).

The implementation uses the
[Gabi](https://github.com/privacybydesign/gabi) cryptographic
library and the corresponding CLI
[irmatool](https://gitlab.informatik.uni-bremen.de/stadlers/irmatool).

Note that the implementation was provided as a Proof of Concept and
is not ready for real-world applications.

We also provide example configuration files. Their content is
fictional and possible overlaps with real-world entities are
unintended.


LICENSE INFORMATION
===================

This library is published as open-source software without any warranty
of any kind. Use is permitted under the terms of the MIT license.
Please refer to LICENSE for further details.

