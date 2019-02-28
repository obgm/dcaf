# tests/Makefile.am
#
# Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of dcaf. Please see README and COPYING for terms
# of use.

CATCH_HPP=https://raw.githubusercontent.com/CatchOrg/Catch2/master/single_include/catch.hpp

if BUILD_TESTS

# picking up the default warning CFLAGS into AM_CXXFLAGS
AM_CXXFLAGS = -I$(top_builddir)/include -I$(top_srcdir)/include $(WARNING_CXXFLAGS) -std=c++14
AM_CPPFLAGS = @libcoap_CFLAGS@
AM_LDFLAGS = -L$(top_builddir) -ljansson
libs = -ldcaf  @libcoap_LIBS@ @cn_cbor_LIBS@

noinst_PROGRAMS = testdriver

testdriver_DEPENDENCIES = $(top_builddir)/libdcaf.a

testdriver_SOURCES = \
 testdriver.cc \
 test_abc.cc\
 test_abc_message.cc\
 test_access_rules.cc\
 test_configuration.cc
 

testdriver_LDADD = $(libs)

CLEANFILES = testdriver

#testdriver:: catch.hpp

catch.hpp:
	curl -o $@ $(CATCH_HPP)

endif # BUILD_TESTS
