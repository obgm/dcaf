dcaf: Authenticated Authorization for the Internet of Things

Copyright (c) 2015—2021 by Olaf Bergmann <bergmann@tzi.org>
              2015—2021 by Stefanie Gerdes <gerdes@tzi.org>

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
https://dcaf.science

PREREQUISITES
=============

The following packages are required for building libdcaf:

* [libcoap](https://libcoap.net) version 4.2 or above, build with
  either OpenSSL, Mbed TLS, or tinydtls.
* [yaml-cpp](https://github.com/jbeder/yaml-cpp)
* [cn-cbor](https://github.com/jimsch/cn-cbor)

BUILDING
========

1. First, run `autogen.sh` to create the required autoconf files, then
2. do `configure`, followed by
3. `make`
4. and `make install` if required.

LICENSE INFORMATION
===================

This library is published as open-source software without any warranty
of any kind. Use is permitted under the terms of the MIT license.
Please refer to LICENSE for further details.

For unit tests, this software package includes
[Catch2](https://github.com/catchorg/Catch2) which is distributed
under the Boost Software License, Version 1.0.
