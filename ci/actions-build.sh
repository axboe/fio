#!/bin/bash
# This script expects to be invoked from the base fio directory.
set -eu

SCRIPT_DIR=$(dirname "$0")
# shellcheck disable=SC1091
. "${SCRIPT_DIR}/common.sh"

main() {
    local extra_cflags="-Werror"
    local configure_flags=()

    set_ci_target_os
    case "${CI_TARGET_OS}" in
        "linux")
            case "${CI_TARGET_ARCH}" in
                "i686")
                    extra_cflags="${extra_cflags} -m32"
                    export LDFLAGS="-m32"
                    ;;
                "x86_64")
                    configure_flags+=(
                        "--enable-cuda"
                        "--enable-libiscsi"
                        "--enable-libnbd"
                    )
                    ;;
            esac
        ;;
    esac
    configure_flags+=(--extra-cflags="${extra_cflags}")

    ./configure "${configure_flags[@]}"
    make -j 2
}

main
