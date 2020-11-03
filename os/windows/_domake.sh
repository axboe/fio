#!/usr/bin/env bash

set -e

cd "$2"
cd ../..
if [ -e "fio.exe" ]; then
  make clean
fi

if [ "$1" = "x86" ]; then
  ./configure --disable-native --build-32bit-win
else
  ./configure --disable-native
fi

make -j
