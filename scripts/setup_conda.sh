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

mkdir -p $HOME/.irods
cat <<EOF > $HOME/.irods/irods_environment.json
{
    "irods_host": "irods",
    "irods_port": 1247,
    "irods_user_name": "irods",
    "irods_zone_name": "testZone",
    "irods_home": "/testZone/home/irods",
    "irods_plugins_home": "$CONDA_INSTALL_DIR/envs/github/lib/irods/plugins/",
    "irods_default_resource": "testResc"
}
EOF

echo "irods" | script -q -c "iinit" /dev/null
ienv
ils
