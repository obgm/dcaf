# examples/Makefile.am
#
# Copyright (c)      2017-2021 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

# picking up the default warning CFLAGS into AM_CFLAGS
AM_CXXFLAGS = -std=c++20
AM_CPPFLAGS = -I @top_builddir@/include $(yaml_cpp_CFLAGS) $(WARNING_CXXFLAGS) @libcoap_CFLAGS@

AM_LDFLAGS = -L@top_builddir@

bin_PROGRAMS = dcaf-am

dcaf_am_DEPENDENCIES = $(top_builddir)/libdcaf.a

dcaf_am_includedir = $(top_builddir)/am
dcaf_am_SOURCES = am.cc config_parser.cc coap_config.cc db.cc
dcaf_am_CXXFLAGS = $(AM_CXXFLAGS) $(sqlite_CFLAGS)
dcaf_am_LDADD = -ldcaf @libcoap_LIBS@ @cn_cbor_LIBS@ $(yaml_cpp_LIBS) $(sqlite_LIBS)

## Additional files for the distribution archive
EXTRA_DIST = \
  coap_config.cc   \
  config_parser.hh \
  db.hh \
  rule.hh
