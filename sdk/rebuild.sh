#!/bin/bash

set -e

rm -rf build*
mkdir build
pushd build
cmake ..
make -j16
make install
popd
