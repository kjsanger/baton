#!/bin/bash

set -ex

source "$CONDA_INSTALL_DIR/etc/profile.d/conda.sh"

conda activate base
conda config --add channels https://dnap.cog.sanger.ac.uk/npg/conda/devel/generic/
conda config --add channels https://dnap.cog.sanger.ac.uk/npg/conda/tools/generic/

conda create -y -n github
conda activate github

conda install -y libjansson-dev
conda install -y libssl-dev
conda install -y irods-dev
conda install -y irods-icommands
conda install check

conda install -y autoconf
conda install -y automake
conda install -y libtool
conda install -y make
conda install pkg-config
