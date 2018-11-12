# examples/Makefile.am
#
# Copyright (c)      2016-2018 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

# picking up the default warning CFLAGS into AM_CFLAGS
AM_CFLAGS = -I @top_builddir@/include $(WARNING_CFLAGS)
AM_CPPFLAGS = @libcoap_CFLAGS@

AM_LDFLAGS = -L@top_builddir@

libs = $(top_builddir)/libdcaf.a @libcoap_LIBS@ @cn_cbor_LIBS@
bin_PROGRAMS = s dcaf-client

s_SOURCES = s.c
s_LDADD = $(libs)

dcaf_client_SOURCES = dcaf-client.c
dcaf_client_LDADD = $(libs)
