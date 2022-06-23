#!/bin/bash
# This script expects to be invoked from the base fio directory.
set -eu

main() {
    [ "${CI_TARGET_BUILD}" = "android" ] && return 0

    echo "Running smoke tests..."
    make test
}

main
