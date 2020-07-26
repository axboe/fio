#!/bin/bash
# This script expects to be invoked from the base fio directory.
set -eu

main() {
    echo "Running smoke tests..."
    make test
}

main
