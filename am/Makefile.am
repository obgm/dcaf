# examples/Makefile.am
#
# Copyright (c)      2017-2018 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

# picking up the default warning CFLAGS into AM_CFLAGS
AM_CXXFLAGS = -std=c++17
AM_CPPFLAGS = -I @top_builddir@/include @lug_CXXFLAGS@ $(WARNING_CXXFLAGS) @libcoap_CFLAGS@

AM_LDFLAGS = -L@top_builddir@ -ljansson

bin_PROGRAMS = dcaf-abc dcaf-abc-client

dcaf_abc_DEPENDENCIES = $(top_builddir)/libdcaf.a

dcaf_abc_includedir = $(top_builddir)/am
dcaf_abc_include_HEADERS = config_parser.hh am_util.hh
dcaf_abc_SOURCES = am_abc.cc config_parser.cc am_util.cc
dcaf_abc_CXXFLAGS = $(AM_CXXFLAGS)
dcaf_abc_CPPFLAGS = $(filter-out -Wswitch-enum -fpermissive -Winline, $(AM_CPPFLAGS))
dcaf_abc_LDADD = -ldcaf @libcoap_LIBS@ @cn_cbor_LIBS@

dcaf_abc_client_DEPENDENCIES = $(top_builddir)/libdcaf.a

dcaf_abc_client_includedir = $(top_builddir)/am
dcaf_abc_client_include_HEADERS = am_util.hh
dcaf_abc_client_SOURCES = dcaf_am_test_client.cc am_util.cc
dcaf_abc_client_CXXFLAGS = $(AM_CXXFLAGS)
dcaf_abc_client_CPPFLAGS = $(filter-out -Wswitch-enum -fpermissive -Winline, $(AM_CPPFLAGS))
dcaf_abc_client_LDADD = -ldcaf @libcoap_LIBS@ @cn_cbor_LIBS@
