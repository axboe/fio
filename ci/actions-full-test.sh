#!/bin/bash
# This script expects to be invoked from the base fio directory.
set -eu

main() {
    case "${CI_TARGET_BUILD}" in
	android*)
	    return 0;;
    esac

    echo "Running long running tests..."
    export PYTHONUNBUFFERED="TRUE"
    python3 t/run-fio-tests.py --skip 6 1007 1008 --debug
    make -C doc html
}

main
