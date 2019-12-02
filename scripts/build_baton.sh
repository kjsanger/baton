#!/bin/bash

set -ex

source "$CONDA_INSTALL_DIR/etc/profile.d/conda.sh"

conda activate github

CONDA_ENV="$CONDA_INSTALL_DIR/envs/github"
CPPFLAGS="-I$CONDA_ENV/include -I$CONDA_ENV/include/irods"
LDFLAGS="-L$CONDA_ENV/lib -L$CONDA_ENV/lib/irods/externals"

autoreconf -fi

./configure --with-test-resource=testResc \
            CPPFLAGS="$CPPFLAGS" LDFLAGS="$LDFLAGS"

export LD_LIBRARY_PATH="$CONDA_ENV/lib"
export CK_DEFAULT_TIMEOUT=20

make distcheck DISTCHECK_CONFIGURE_FLAGS="--with-test-resource=demoResc CPPFLAGS=\"$CPPFLAGS\" LDFLAGS=\"$LDFLAGS\""
