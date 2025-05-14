#!/usr/bin/env bash
# This script expects to be invoked from the base fio directory.
set -eu

SCRIPT_DIR=$(dirname "$0")
# shellcheck disable=SC1091
. "${SCRIPT_DIR}/common.sh"

_sudo() {
    if type -P sudo >/dev/null; then
        sudo "$@"
    else
        "$@"
    fi
}

install_ubuntu() {
    local pkgs

    cat <<DPKGCFG | _sudo tee /etc/dpkg/dpkg.cfg.d/dpkg-speedup > /dev/null
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
	libgnutls28-dev
        libnuma-dev
	libnfs-dev
        valgrind
    )
    case "${CI_TARGET_ARCH}" in
        "i686")
            _sudo dpkg --add-architecture i386
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
                librbd-dev
                libtcmalloc-minimal4
                libibverbs-dev
                librdmacm-dev
	        pkg-config
            )
	    if apt list --installed | grep -c "libunwind-14-dev"; then
		    echo "Removing libunwind-14-dev because of conflicts with libunwind-dev"
		    _sudo apt remove -y libunwind-14-dev
	    fi
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
	sudo
	${EXTRA_PKGS:-}
    )
    if [ "${GITHUB_JOB}" == "build-containers" ] || [ "${GITHUB_JOB}" == "qemu-guest" ]; then
        pkgs+=(
            bison
            build-essential
            flex
            procps
            zlib1g-dev
        )
    fi

    echo "Updating APT..."
    _sudo apt-get -qq update
    echo "Installing packages... ${pkgs[@]}"
    _sudo apt-get install -o APT::Immediate-Configure=false --no-install-recommends -qq -y "${pkgs[@]}"
}

# Fedora and related distributions
install_fedora() {
    pkgs=(
        bison-devel
        git
        flex-devel
	gnutls-devel
        gperftools
        isa-l-devel
        kernel-devel
        libaio-devel
        libibverbs-devel
        libiscsi-devel
        libnbd-devel
        libnfs-devel
        libpmem-devel
        libpmem2-devel
        librbd-devel
        numactl-devel
        protobuf-c-devel
        python3-scipy
        python3-sphinx
        sudo
        valgrind-devel
	${EXTRA_PKGS:-}
    )

    case "${CI_TARGET_OS}" in
        "fedora")
            pkgs+=(
                cunit-devel
                libgfapi-devel
                python3-statsmodels
            )
            ;;
        "rocky" | "alma" | "oracle")
            pkgs+=(
                CUnit-devel
                python-pip
            )
            ;;&
        "rocky" | "alma")
            pkgs+=(
                glusterfs-api-devel
            )
            ;;
    esac
    dnf install -y "${pkgs[@]}"
}

install_rhel_clone() {
    dnf install -y epel-release
    install_fedora

    # I could not find a python3-statsmodels package in the repos
    pip3 install statsmodels
}

install_oracle() {
    dnf config-manager --set-enabled ol9_codeready_builder
    install_rhel_clone
}

install_alma() {
    dnf install -y 'dnf-command(config-manager)'
    dnf config-manager --set-enabled crb
    dnf install -y almalinux-release-devel
    install_rhel_clone
}

install_rocky() {
    dnf install -y 'dnf-command(config-manager)'
    dnf config-manager --set-enabled crb
    dnf config-manager --set-enabled devel
    install_rhel_clone
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
    HOMEBREW_NO_AUTO_UPDATE=1 brew install cunit libnfs
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
