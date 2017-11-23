# examples/Makefile.am
#
# Copyright (c)      2017 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

# picking up the default warning CFLAGS into AM_CFLAGS
AM_CXXFLAGS = -I @top_builddir@/include $(WARNING_CXXFLAGS) -std=c++14

# retrieve crypto libs used for libcoap */
private_libs=$(shell sed -ne 's/^Libs.private://p' `pkg-config --variable=pcfiledir libcoap-1`/libcoap-1.pc)
AM_LDFLAGS = -L@top_builddir@ @libcoap_LIBS@ @cn_cbor_LIBS@ $(private_libs)

bin_PROGRAMS = dcaf-am

dcaf_am_SOURCES = am.cc
dcaf_am_LDADD = -ldcaf

