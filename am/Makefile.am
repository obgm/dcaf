# examples/Makefile.am
#
# Copyright (c)      2017-2018 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

# picking up the default warning CFLAGS into AM_CFLAGS
AM_CXXFLAGS = -std=c++17
AM_CPPFLAGS = -I @top_builddir@/include @lug_CXXFLAGS@ $(WARNING_CXXFLAGS) @libcoap_CFLAGS@

AM_LDFLAGS = -L@top_builddir@

bin_PROGRAMS = dcaf-am am-config

dcaf_am_DEPENDENCIES = $(top_builddir)/libdcaf.a

dcaf_am_SOURCES = am.cc config_parser.cc
dcaf_am_CXXFLAGS = $(AM_CXXFLAGS)
dcaf_am_CPPFLAGS = $(filter-out -Wswitch-enum -fpermissive -Winline, $(AM_CPPFLAGS))
dcaf_am_LDADD = -ldcaf @libcoap_LIBS@ @cn_cbor_LIBS@

am_config_CXXFLAGS = $(AM_CXXFLAGS)
am_config_CPPFLAGS = $(filter-out -Wswitch-enum -fpermissive -Winline, $(AM_CPPFLAGS))
am_config_SOURCES = am-config.cc config_parser.cc

#FIXME: extra dist files: config_parser.hh
