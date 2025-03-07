# shellcheck shell=bash

function set_ci_target_os {
    # Function that exports CI_TARGET_OS to the current OS if it is not already
    # set.

    # Don't override CI_TARGET_OS if already set
    CI_TARGET_OS=${CI_TARGET_OS:-}
    if [[ -z ${CI_TARGET_OS} ]]; then
        # Detect operating system
        case "${OSTYPE}" in
            linux*)
                CI_TARGET_OS="linux"
                ;;
            darwin*)
                CI_TARGET_OS="macos"
                ;;
            cygwin|msys*)
                CI_TARGET_OS="windows"
                ;;
            bsd*)
                CI_TARGET_OS="bsd"
                ;;
            *)
                CI_TARGET_OS=""
        esac
    fi

    # Don't override CI_TARGET_ARCH if already set
    CI_TARGET_ARCH=${CI_TARGET_ARCH:-}
    if [[ -z ${CI_TARGET_ARCH} ]]; then
        CI_TARGET_ARCH="$(uname -m)"
    fi
}
