#!/bin/bash -e

# 11.02.2021 Merge pull request #866 from ldorau/rpma-mmap-memory-for-rpma_mr_reg-in-rpma_flush_apm_new
LIBRPMA_VERSION=fbac593917e98f3f26abf14f4fad5a832b330f5c
ZIP_FILE=rpma.zip

WORKDIR=$(pwd)

# install librpma
wget -O $ZIP_FILE https://github.com/pmem/rpma/archive/${LIBRPMA_VERSION}.zip
unzip $ZIP_FILE
mkdir -p rpma-${LIBRPMA_VERSION}/build
cd rpma-${LIBRPMA_VERSION}/build
cmake .. -DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DBUILD_DOC=OFF \
	-DBUILD_EXAMPLES=OFF \
	-DBUILD_TESTS=OFF
make -j$(nproc)
sudo make -j$(nproc) install
cd $WORKDIR
rm -rf $ZIP_FILE rpma-${LIBRPMA_VERSION}
