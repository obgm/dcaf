# examples/Makefile.am
#
# Copyright (c)      2017-2018 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

# picking up the default warning CFLAGS into AM_CFLAGS
AM_CXXFLAGS = -I @top_builddir@/include $(WARNING_CXXFLAGS) -std=c++14
AM_CPPFLAGS = @libcoap_CFLAGS@

AM_LDFLAGS = -L@top_builddir@

bin_PROGRAMS = dcaf-am

dcaf_am_DEPENDENCIES = $(top_builddir)/libdcaf.a

dcaf_am_SOURCES = am.cc
dcaf_am_LDADD = -ldcaf @libcoap_LIBS@ @cn_cbor_LIBS@

