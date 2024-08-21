#!/bin/bash
# This script expects to be invoked from the base fio directory.
set -eu

SCRIPT_DIR=$(dirname "$0")
# shellcheck disable=SC1091
. "${SCRIPT_DIR}/common.sh"

install_ubuntu() {
    local pkgs

    if [ "${GITHUB_JOB}" == "build-containers" ]; then
        # containers run as root and do not have sudo
        apt update
        apt -y install sudo
    fi

    cat <<DPKGCFG | sudo tee /etc/dpkg/dpkg.cfg.d/dpkg-speedup > /dev/null
# Skip fsync
force-unsafe-io
# Don't install documentation
path-exclude=/usr/share/man/*
path-exclude=/usr/share/locale/*/LC_MESSAGES/*.mo
path-exclude=/usr/share/doc/*
DPKGCFG

    # Packages available on i686 and x86_64
    pkgs=(
        libaio-dev
        libcunit1-dev
        libcurl4-openssl-dev
        libfl-dev
        libnuma-dev
	libnfs-dev
        valgrind
    )
    case "${CI_TARGET_ARCH}" in
        "i686")
            sudo dpkg --add-architecture i386
            pkgs=("${pkgs[@]/%/:i386}")
            pkgs+=(
                gcc-multilib
                pkg-config:i386
                zlib1g-dev:i386
                libc6:i386
                libgcc-s1:i386
            )
            ;;
        "x86_64")
            pkgs+=(
                libglusterfs-dev
                libgoogle-perftools-dev
                libisal-dev
                libiscsi-dev
                libnbd-dev
                libpmem-dev
                libpmem2-dev
                libprotobuf-c-dev
                librbd-dev
                libtcmalloc-minimal4
                libibverbs-dev
                librdmacm-dev
	        pkg-config
            )
	    echo "Removing libunwind-14-dev because of conflicts with libunwind-dev"
	    sudo apt remove -y libunwind-14-dev
	    if [ "${CI_TARGET_OS}" == "linux" ] || [ "${CI_TARGET_OS}" == "ubuntu" ]; then
	        # Only for Ubuntu
		pkgs+=(
		   nvidia-cuda-dev
		)
	    fi
            ;;
    esac

    # Architecture-independent packages and packages for which we don't
    # care about the architecture.
    pkgs+=(
        python3-scipy
	python3-sphinx
	python3-statsmodels
    )
    if [ "${GITHUB_JOB}" == "build-containers" ]; then
        pkgs+=(
            bison
            build-essential
            cmake
            flex
            unzip
            wget
            zlib1g-dev
        )
    fi

    echo "Updating APT..."
    sudo apt-get -qq update
    echo "Installing packages... ${pkgs[@]}"
    sudo apt-get install -o APT::Immediate-Configure=false --no-install-recommends -qq -y "${pkgs[@]}"
    if [ "${CI_TARGET_ARCH}" == "x86_64" ]; then
        # install librpma from sources
        ci/actions-install-librpma.sh
    fi
}

install_fedora() {
    dnf install -y \
        bison-devel \
        cmake \
        cunit-devel \
        flex-devel \
        isa-l-devel \
        kernel-devel \
        libaio-devel \
        libgfapi-devel \
        libibverbs-devel \
        libiscsi-devel \
        libnbd-devel \
        libnfs-devel \
        libpmem-devel \
        libpmem2-devel \
        librbd-devel \
        numactl-devel \
        protobuf-c-devel \
        python3-scipy \
        python3-sphinx \
        python3-statsmodels \
        unzip \
        valgrind-devel \
        wget \

    # install librpma from sources
    ci/actions-install-librpma.sh
}

install_debian() {
    install_ubuntu
}

install_linux() {
    install_ubuntu
}

install_macos() {
    # Assumes homebrew and python3 are already installed
    #echo "Updating homebrew..."
    #brew update >/dev/null 2>&1
    echo "Installing packages..."
    HOMEBREW_NO_AUTO_UPDATE=1 brew install cunit libnfs bash
    pip3 install scipy six statsmodels sphinx
}

install_windows() {
	pip3 install scipy six statsmodels sphinx
}

main() {
    case "${CI_TARGET_BUILD}" in
	android*)
	    echo "Installing Android NDK..."
	    wget --quiet https://dl.google.com/android/repository/android-ndk-r24-linux.zip
	    unzip -q android-ndk-r24-linux.zip
	    return 0
	    ;;
    esac

    set_ci_target_os

    install_function="install_${CI_TARGET_OS}"
    ${install_function}

    echo "Python3 path: $(type -p python3 2>&1)"
    echo "Python3 version: $(python3 -V 2>&1)"
}

main
