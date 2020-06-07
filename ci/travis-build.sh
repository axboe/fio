#!/bin/bash

EXTRA_CFLAGS="-Werror"

if [[ "$BUILD_ARCH" == "x86" ]]; then
    EXTRA_CFLAGS="${EXTRA_CFLAGS} -m32"
fi

./configure --extra-cflags="${EXTRA_CFLAGS}" &&
    make &&
    make test &&
    if [[ "$TRAVIS_CPU_ARCH" == "arm64" ]]; then
	sudo python3 t/run-fio-tests.py --skip 6 1007 1008 --debug -p 1010:"--skip 15 16 17 18 19 20"
    else
	sudo python3 t/run-fio-tests.py --skip 6 1007 1008 --debug
    fi
