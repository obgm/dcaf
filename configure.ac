#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Copyright (c) 2016 Olaf Bergmann (TZI)

AC_PREREQ([2.64])
AC_INIT([dcaf], [0.1.0])
AM_INIT_AUTOMAKE([1.10 -Wall no-define no-dist-gzip dist-bzip2])
PKG_PROG_PKG_CONFIG([0.20])

AM_SILENT_RULES([yes])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB
AM_PROG_AR

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

AC_SUBST([WARNING_CFLAGS])

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
AC_CHECK_FUNCS([memset])

PKG_CHECK_MODULES([cn_cbor], [cn-cbor])
PKG_CHECK_MODULES([libcoap], [libcoap-1], [have_libcoap="yes"])

if test "x$have_libcoap" = "xyes"; then
   # FIXME: this works only with bash parameter substitution and pkg-config
   libcoap_L=`pkg-config --libs-only-L libcoap-1`
   libcoap_LIBS="-Wl,-rpath=${libcoap_L:2} $libcoap_LIBS"
fi

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
                 as/Makefile
                 examples/Makefile])
AC_OUTPUT
