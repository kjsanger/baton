#!/bin/sh

set -ex

n="$CPU_COUNT"

export LD_LIBRARY_PATH="$PREFIX/lib"

autoreconf -fi

./configure --prefix="$PREFIX" --with-test-resource=demoResc \
            CPPFLAGS="-I$PREFIX/include -I$PREFIX/include/irods" \
            LDFLAGS="-L$PREFIX/lib -L$PREFIX/lib/irods/externals"

export CK_DEFAULT_TIMEOUT=20

make -j $n distcheck DISTCHECK_CONFIGURE_FLAGS="--with-test-resource=demoResc CPPFLAGS=\"$CPPFLAGS\" LDFLAGS=\"$LDFLAGS\""

