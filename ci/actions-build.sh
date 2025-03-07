#!/usr/bin/env bash
# This script expects to be invoked from the base fio directory.
set -eu

SCRIPT_DIR=$(dirname "$0")
# shellcheck disable=SC1091
. "${SCRIPT_DIR}/common.sh"

main() {
    local extra_cflags="-Werror"
    local configure_flags=()

    set_ci_target_os
    case "${CI_TARGET_BUILD}/${CI_TARGET_OS}" in
        android*/*)
            export UNAME=Android
            if [ -z "${CI_TARGET_ARCH}" ]; then
                echo "Error: CI_TARGET_ARCH has not been set"
                return 1
            fi
            NDK=$PWD/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin
            export PATH="${NDK}:${PATH}"
            if [ "${CI_TARGET_BUILD}" = "android" ]; then
                export LIBS="-landroid"
            fi
            CC=${NDK}/${CI_TARGET_ARCH}-clang
            if [ ! -e "${CC}" ]; then
                echo "Error: could not find ${CC}"
                return 1
            fi
            ;;
        */linux | */ubuntu)
            case "${CI_TARGET_ARCH}" in
                "x86_64")
                    configure_flags+=(
                        "--enable-cuda"
                    )
                    ;;
	    esac
	    ;;&
        */linux | */ubuntu | */debian | */fedora | */alma | */oracle | */rocky)
            case "${CI_TARGET_ARCH}" in
                "i686")
                    extra_cflags="${extra_cflags} -m32"
                    export LDFLAGS="-m32"
                    ;;
                "x86_64")
                    configure_flags+=(
                        "--enable-libiscsi"
                        "--enable-libnbd"
                    )
                    ;;
            esac
	    ;;
        */windows)
	    configure_flags+=("--disable-native")
            case "${CI_TARGET_ARCH}" in
                "i686")
		    configure_flags+=("--build-32bit-win")
                    ;;
                "x86_64")
                    ;;
            esac
            if [ "${CI_TARGET_BUILD}" = "windows-msys2-64" ]; then
                configure_flags+=("--disable-tls")
            fi
	    ;;
    esac
    configure_flags+=(--extra-cflags="${extra_cflags}")

    ./configure "${configure_flags[@]}"
    make -j "$(nproc 2>/dev/null || sysctl -n hw.logicalcpu)"
# macOS does not have nproc, so we have to use sysctl to obtain the number of
# logical CPUs.
}

main
