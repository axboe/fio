#!/bin/bash
# This script expects to be invoked from the base fio directory.
set -eu

main() {
    echo "Running long running tests..."
    export PYTHONUNBUFFERED="TRUE"
    if [[ "${CI_TARGET_ARCH}" == "arm64" ]]; then
        sudo python3 t/run-fio-tests.py --skip 6 1007 1008 --debug -p 1010:"--skip 15 16 17 18 19 20"
    else
        sudo python3 t/run-fio-tests.py --skip 6 1007 1008 --debug
    fi
}

main
