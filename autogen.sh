#!/bin/sh -efu

OPT=
[ "${1-}" != '-f' ] || OPT=-f

#autoreconf -iv $OPT

libtoolize --install --copy --force --automake
aclocal -I m4
autoconf --force
autoheader --force
automake --add-missing --copy --force-missing

echo
echo "Now type '${0%/*}/configure' and 'make' to compile."
echo
