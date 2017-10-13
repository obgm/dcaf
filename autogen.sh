#! /bin/sh -e

srcdir=`dirname "$0"`

GENERATED_FILES="aclocal.m4 ar-lib compile depcomp src/.dirstamp
               Makefile Makefile.in examples/Makefile examples/Makefile.in
               config.status configure config.log
               dcaf_config.h dcaf_config.h.in"

GENERATED_DIRS="autom4te.cache src/.deps"

if test "x$1" = "x--clean"; then
    rm -f $GENERATED_FILES
    rm -rf $GENERATED_DIRS
    exit 0
fi

autoreconf --force --install --verbose "$srcdir"
