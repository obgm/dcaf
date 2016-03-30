#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Copyright (c) 2016 Olaf Bergmann (TZI)

AC_PREREQ([2.64])
AC_INIT([dcaf], [0.1.0])
AM_INIT_AUTOMAKE([1.10 -Wall no-define no-dist-gzip dist-bzip2])

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

AC_CONFIG_HEADERS([dcaf_config.h])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
