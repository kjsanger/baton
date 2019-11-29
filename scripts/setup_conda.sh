#!/bin/bash

set -ex

source $CONDA_INSTALL_DIR/etc/profile.d/conda.sh

conda activate base
conda config --add channels https://dnap.cog.sanger.ac.uk/npg/conda/devel/generic/

conda create -y -n github
conda activate github
conda install -y libjansson-dev
conda install -y irods-dev
conda install -y irods-icommands
