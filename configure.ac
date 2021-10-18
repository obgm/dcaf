#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Copyright (c) 2016-2020 Olaf Bergmann (TZI)

AC_PREREQ([2.64])
AC_INIT([dcaf], [0.1.0])
AM_INIT_AUTOMAKE([1.10 -Wall no-define no-dist-gzip dist-bzip2])
PKG_PROG_PKG_CONFIG([0.20])

AM_SILENT_RULES([yes])

AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR

# C++
AC_PROG_CXX

# Adding some default warning options for code QS
# see https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html
# and http://www.gnu.org/software/automake/manual/html_node/Flag-Variables-Ordering.html
WARNING_CFLAGS="\
-pedantic \
-Wall \
-Wextra \
-Wformat-security \
-Winline \
-Wmissing-declarations \
-Wmissing-prototypes \
-Wnested-externs \
-Wpointer-arith \
-Wshadow \
-Wstrict-prototypes \
-Wswitch-default \
-Wswitch-enum \
-Wunused \
-Wunused-result \
"

WARNING_CXXFLAGS="\
-pedantic \
-Wall \
-Wextra \
-Wformat-security \
-Winline \
-Wmissing-declarations \
-Wpointer-arith \
-Wshadow \
-Wswitch-default \
-Wswitch-enum \
-Wunused \
-Wunused-result \
"

AC_SUBST([WARNING_CFLAGS])
AC_SUBST([WARNING_CXXFLAGS])

AC_PATH_PROG(DOXYGEN, doxygen, [:])

AC_ARG_WITH(debug,
  [AS_HELP_STRING([--without-debug],[disable all debug output and assertions])],
  [CPPFLAGS="${CPPFLAGS} -DNDEBUG"
   NDEBUG=1], 
  [])

# Checks for header files.
AC_CHECK_HEADERS([assert.h inttypes.h stddef.h stdint.h stdlib.h string.h strings.h unistd.h])
AC_CHECK_HEADERS([sys/time.h time.h])
AC_CHECK_HEADERS([sys/types.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset getrandom getaddrinfo gai_strerror])

LIBCOAP=libcoap-3
PKG_CHECK_MODULES([cn_cbor], [cn-cbor])
PKG_CHECK_MODULES([libcoap], [$LIBCOAP])

case "$libcoap_LIBS" in
    *-openssl)
   AC_MSG_NOTICE([build $LIBCOAP against OpenSSL])
   PKG_CHECK_MODULES([openssl], [openssl])
   libcoap_CFLAGS="$libcoap_CFLAGS -DCOAP_DTLS_OPENSSL $openssl_CFLAGS"
   libcoap_LIBS="$libcoap_LIBS $openssl_LIBS"
   ;;
    *-mbedtls)
   # There is no pkgconfig for MbedTLS hence we use the default installation
   AC_MSG_NOTICE([build $LIBCOAP against Mbed TLS])
   libcoap_CFLAGS="$libcoap_CFLAGS -DCOAP_DTLS_MBEDTLS"
   MbedTLS_LIBS="-lmbedtls -lmbedcrypto -lmbedx509"
   libcoap_LIBS="$libcoap_LIBS $MbedTLS_LIBS"
   ;;
    *-tinydtls)
   AC_MSG_NOTICE([build $LIBCOAP against tinyDTLS])
   libcoap_CFLAGS="$libcoap_CFLAGS -DCOAP_DTLS_TINYDTLS"
   ;;
    *-gnutls)
   AC_MSG_NOTICE([build $LIBCOAP against GnuTLS])
   PKG_CHECK_MODULES([gnutls], [gnutls])
   libcoap_CFLAGS="$libcoap_CFLAGS -DCOAP_DTLS_GNUTLS $gnutls_CFLAGS"
   AC_MSG_ERROR([Sorry, GnuTLS currently is not supported])
   ;;
    *)
   AC_MSG_ERROR([no TLS library found for libcoap])
   ;;
esac

# __client__
AC_ARG_ENABLE([client],
              [AS_HELP_STRING([--enable-client],
                              [Enable client implementation [default=yes]])],
              [build_client="$enableval"],
              [build_client="yes"])

if test "x$build_client" = "xyes"; then
   AC_DEFINE(CONFIG_DCAF_CLIENT, [1], [Define this to 1 to include DCAF client code])
fi

# __server__
AC_ARG_ENABLE([server],
              [AS_HELP_STRING([--enable-server],
                              [Enable server implementation [default=yes]])],
              [build_server="$enableval"],
              [build_server="yes"])

if test "x$build_server" = "xyes"; then
  AC_DEFINE(CONFIG_DCAF_SERVER, [1], [Define this to 1 to include DCAF server code])
fi

# __am__
AC_ARG_ENABLE([am],
              [AS_HELP_STRING([--enable-am],
                              [Enable authorization manager implementation [default=yes]])],
              [build_am="$enableval"],
              [build_am="yes"])

if test "x$build_am" = "xyes"; then
  AC_DEFINE(CONFIG_DCAF_AM, [1], [Define this to 1 to include DCAF authorization manager code])
fi

# Database support

PKG_CHECK_MODULES([sqlite], [sqlite3],
                  [AC_DEFINE([HAVE_SQLITE], [1],
                             [Enable database support using sqlite3])],
                  [AC_MSG_NOTICE([build AM without database support])])

# __documentation__
AC_ARG_ENABLE([documentation],
              [AS_HELP_STRING([--enable-documentation],
                              [Enable doxygen-generated documentation [default=yes]])],
              [build_docs="$enableval"])

AC_CHECK_PROG([DOXYGEN], [doxygen])
AM_CONDITIONAL(BUILD_DOCUMENTATION, [test "x$build_docs" != "xno"])

# __tests__
AC_ARG_ENABLE([tests],
              [AS_HELP_STRING([--enable-tests],
                              [Enable building the binary testsuite [default=no]])],
              [build_tests="$enableval"],
              [build_tests="no"])

AM_CONDITIONAL(BUILD_TESTS, [test "x$build_tests" != "xno"])

# __am__
AC_ARG_ENABLE([am],
              [AS_HELP_STRING([--enable-am],
                              [Enable building the authorization manager [default=yes]])],
              [build_am="$enableval"],
              [build_am="yes"])

AS_IF([test "x$build_am" != "xno"], [
   PKG_CHECK_MODULES([yaml_cpp], [yaml-cpp])
   am_DIR=am
])
AC_SUBST(am_DIR)

AC_CONFIG_HEADERS([dcaf_config.h])

AC_MSG_CHECKING([operating system])

# FIXME:
host=-linux

# Set up here some extra platform depended defines and variables.
# The "ADDITIONAL_CFLAGS" is need as this stand-alone definition
# for the doxygen part.
case $host in
	*-linux* | *-uclinux*)
	AC_MSG_RESULT([Linux])
	ADDITIONAL_CFLAGS="-D_GNU_SOURCE -DWITH_POSIX"
        PLATFORM=posix

	# Not yet needed but if some code definitions have to depend on the platform.
	#AC_DEFINE(OS_LINUX, 1, [Linux backend])
	#AC_SUBST(OS_LINUX)
	;;

	*-solaris*)
	AC_MSG_RESULT([Solaris])
	# set _XOPEN_SOURCE and _XOPEN_SOURCE_EXTENDED to enable XPG4v2 (POSIX 2004)
	# set __EXTENSION__ to shut up feature test macros that restrict -std=c99
	# to only C99 (and nothing newer)
	ADDITIONAL_CFLAGS="-D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED=600 -D__EXTENSIONS__=1 -DWITH_POSIX"
        PLATFORM=posix
	;;

	*-darwin*)
	AC_MSG_RESULT([Darwin])
	ADDITIONAL_CFLAGS="-D_GNU_SOURCE -DWITH_POSIX"
        PLATFORM=posix

	AC_DEFINE(__APPLE_USE_RFC_3542, 1, [Define this to 1 for ancillary data on MacOS])

	# Not yet needed but if some code definitions have to depend on the platform.
	#AC_DEFINE(OS_MACOS, 1, [MacOS backend])
	#AC_SUBST(OS_MACOS)
	;;

	*)
	AC_MSG_WARN([unsupported operating system ${host}!])
esac

# Export platform definition
AC_SUBST(PLATFORM)

AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 tests/Makefile
                 am/Makefile
                 examples/Makefile
                 include/dcaf/libdcaf.h])
AC_OUTPUT
