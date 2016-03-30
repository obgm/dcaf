#! /bin/sh -e

srcdir=`dirname "$0"`
cbordir="$srcdir/ext/cn-cbor"

if test -x "$cbordir/build.sh"; then
    (cd "$cbordir" && ./build.sh)
else
    echo "Error: cannot find cn-cbor" >&2
fi

autoreconf --force --install --verbose "$srcdir"
