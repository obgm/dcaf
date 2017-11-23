# Makefile.am for dcaf
#
# Copyright (C) 2016-2017 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of the library dcaf. Please see README and
# COPYING for terms of use.

## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

## Additional files for the distribution archive
EXTRA_DIST = $(pkgconfig_DATA).in

AM_CPPFLAGS = @libcoap_CFLAGS@ @cn_cbor_CFLAGS@

SUBDIRS = $(subdirs) . am examples

lib_LIBRARIES = libdcaf.a

libdcaf_a_CFLAGS = -I @top_builddir@/include $(WARNING_CFLAGS)

## Source files comprising libdcaf.
libdcaf_a_SOURCES = \
   src/cose.c \
   src/dcaf.c \
   src/dcaf_crypto_openssl.c \
   src/dcaf_optlist.c \
   src/dcaf_prng.c \
   src/dcaf_transaction.c \
   src/platform/@PLATFORM@/dcaf_address.c

## Public header files and their installation location.
libdcaf_includedir = $(includedir)/dcaf/
libdcaf_include_HEADERS = \
   include/dcaf/ace.h \
   include/dcaf/cose.h \
   include/dcaf/dcaf.h \
   include/dcaf/dcaf_crypto.h \
   include/dcaf/dcaf_int.h \
   include/dcaf/dcaf_optlist.h \
   include/dcaf/dcaf_prng.h \
   include/dcaf/dcaf_transaction.h \
   include/dcaf/dcaf_address.h

## Include autogen.sh in distribution but do not install it.
dist_noinst_SCRIPTS = autogen.sh
