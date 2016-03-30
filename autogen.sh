#! /bin/sh -e

srcdir=`dirname "$0"`

autoreconf --force --install --verbose "$srcdir"
