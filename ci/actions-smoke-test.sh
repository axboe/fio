#!/bin/bash
# This script expects to be invoked from the base fio directory.
set -eu

main() {
    case "${CI_TARGET_BUILD}" in
	android*)
	    return 0;;
    esac

    echo "Running smoke tests..."
    make test
}

main
