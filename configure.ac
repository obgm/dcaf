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

PKG_CHECK_MODULES([cn_cbor], [cn-cbor])
PKG_CHECK_MODULES([libcoap], [libcoap-2-mbedtls], [have_libcoap="libcoap-2-mbedtls"],
   [PKG_CHECK_MODULES([libcoap], [libcoap-2-openssl], [have_libcoap="libcoap-2-openssl"],
      [PKG_CHECK_MODULES([libcoap], [libcoap-2-tinydtls], [have_libcoap="libcoap-2-tinydtls"],
        [PKG_CHECK_MODULES([libcoap], [libcoap-2], [have_libcoap="libcoap-2"])]
      )]
   )]
)

if test "x$have_libcoap" != "xno"; then
   # FIXME: this works only with bash parameter substitution and pkg-config
   libcoap_L=`pkg-config --libs-only-L $have_libcoap`
   libcoap_LIBS="-Wl,-rpath=${libcoap_L:2} $libcoap_LIBS"

   # We want to use the same crypto libs as libcoap uses
   case "$have_libcoap" in
       *-openssl)
      PKG_CHECK_MODULES([OpenSSL], [openssl])
      libcoap_CFLAGS="$libcoap_CFLAGS $OpenSSL_CFLAGS -DCOAP_DTLS_OPENSSL"
      libcoap_LIBS="$libcoap_LIBS $OpenSSL_LIBS"
      ;;
       *-mbedtls)
      # There is no pkgconfig for MbedTLS hence we use the default installation
      MbedTLS_CFLAGS=""
      MbedTLS_LIBS="-lmbedtls -lmbedcrypto -lmbedx509"
      libcoap_CFLAGS="$libcoap_CFLAGS $MbedTLS_CFLAGS -DCOAP_DTLS_MBEDTLS"
      libcoap_LIBS="$libcoap_LIBS $MbedTLS_LIBS"
      ;;
       *-tinydtls)
      libcoap_CFLAGS="$libcoap_CFLAGS -DCOAP_DTLS_TINYDTLS"
      libcoap_LIBS="$libcoap_LIBS -ltinydtls"
      ;;
   esac
fi

# __documentation__
AC_ARG_ENABLE([documentation],
              [AS_HELP_STRING([--enable-documentation],
                              [Enable doxygen-generated documentation [default=yes]])],
              [build_docs="yes"],
              [build_docs="$enableval"])

AC_CHECK_PROG([DOXYGEN], [doxygen])
AM_CONDITIONAL(BUILD_DOCUMENTATION, [test "x$build_docs" != "xno"])

# __tests__
AC_ARG_ENABLE([tests],
              [AS_HELP_STRING([--enable-tests],
                              [Enable building the binary testsuite [default=yes]])],
              [build_tests="yes"],
              [build_tests="$enableval"])

AM_CONDITIONAL(BUILD_TESTS, [test "x$build_tests" != "xno"])

# __am__
AC_ARG_ENABLE([am],
              [AS_HELP_STRING([--enable-am],
                              [Enable building the authorization manager [default=yes]])],
              [build_am="$enableval"],
              [build_am="yes"])

AS_IF([test "x$build_am" != "xno"], [
   AC_CACHE_CHECK([for lug], [ac_cv_lug], [
       AS_IF([test -d ext/lug/lug],
                                    [ av_cv_lug=ext/lug/lug
                                      AC_MSG_RESULT([yes])
                                    ],
                                    [AC_MSG_RESULT([no])])])
    if test "x$av_cv_lug" = "x"; then
       AC_MSG_ERROR([cannot find lug. Try `git submodule update --init` or configure with --disable-am.])
    fi
    am_DIR=am
    lug_CXXFLAGS="-I\$(top_srcdir)/ext/lug"
])
AC_SUBST(am_DIR)
AC_SUBST(lug_CXXFLAGS)

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
