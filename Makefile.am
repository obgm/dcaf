# Makefile.am for dcaf
#
# Copyright (C) 2016-2018 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of the library dcaf. Please see README and
# COPYING for terms of use.

## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

## Additional files for the distribution archive
EXTRA_DIST = \
  CONTRIBUTE \
  TODO \
  LICENSE \
  $(pkgconfig_DATA).in \
  include/dcaf/utlist.h \
  tests/catch.hpp \
  tests/test.hh

AM_CPPFLAGS = @libcoap_CFLAGS@ @cn_cbor_CFLAGS@
AM_CPPFLAGS += -DDCAF_TEST_MODE_ACCEPT=1

SUBDIRS = $(subdirs) . tests @am_DIR@ examples

lib_LIBRARIES = libdcaf.a

libdcaf_a_CFLAGS = -I @top_builddir@/include $(WARNING_CFLAGS)

## Source files comprising libdcaf.
libdcaf_a_SOURCES = \
   src/aif.c \
   src/anybor.c \
   src/cose.c \
   src/dcaf.c \
   src/dcaf_address.c \
   src/dcaf_am.c \
   src/dcaf_base64.c \
   src/dcaf_coap.c \
   src/dcaf_crypto_openssl.c \
   src/dcaf_crypto_mbedtls.c \
   src/dcaf_crypto_tinydtls.c \
   src/dcaf_debug.c \
   src/dcaf_key.c \
   src/dcaf_mem.c \
   src/dcaf_optlist.c \
   src/dcaf_prng.c \
   src/dcaf_transaction.c \
   src/dcaf_utf8.c

## Public header files and their installation location.
libdcaf_includedir = $(includedir)/dcaf/
libdcaf_include_HEADERS = \
   $(top_srcdir)/include/dcaf/ace.h \
   $(top_srcdir)/include/dcaf/aif.h \
   $(top_srcdir)/include/dcaf/anybor.h \
   $(top_srcdir)/include/dcaf/cose.h \
   $(top_srcdir)/include/dcaf/cose_types.h \
   $(top_srcdir)/include/dcaf/dcaf.h \
   $(top_srcdir)/include/dcaf/dcaf_am.h \
   $(top_srcdir)/include/dcaf/dcaf_base64.h \
   $(top_srcdir)/include/dcaf/dcaf_coap.h \
   $(top_srcdir)/include/dcaf/dcaf_crypto.h \
   $(top_srcdir)/include/dcaf/dcaf_debug.h \
   $(top_srcdir)/include/dcaf/dcaf_int.h \
   $(top_srcdir)/include/dcaf/dcaf_key.h \
   $(top_srcdir)/include/dcaf/dcaf_mem.h \
   $(top_srcdir)/include/dcaf/dcaf_optlist.h \
   $(top_srcdir)/include/dcaf/dcaf_prng.h \
   $(top_srcdir)/include/dcaf/dcaf_transaction.h \
   $(top_srcdir)/include/dcaf/dcaf_address.h \
   $(top_srcdir)/include/dcaf/dcaf_utf8.h \
   $(top_builddir)/include/dcaf/libdcaf.h

## Include autogen.sh in distribution but do not install it.
dist_noinst_SCRIPTS = autogen.sh
