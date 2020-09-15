#!/bin/bash
set -eu

CI_TARGET_ARCH="${BUILD_ARCH:-$TRAVIS_CPU_ARCH}"
case "$TRAVIS_OS_NAME" in
    "linux")
	# Architecture-dependent packages.
	pkgs=(
	    libaio-dev
	    libcunit1-dev
	    libfl-dev
	    libgoogle-perftools-dev
	    libibverbs-dev
	    libiscsi-dev
	    libnuma-dev
	    librbd-dev
	    librdmacm-dev
	    libz-dev
	)
	case "$CI_TARGET_ARCH" in
	    "x86")
		pkgs=("${pkgs[@]/%/:i386}")
		pkgs+=(
		    gcc-multilib
		    pkg-config:i386
	        )
		;;
	    "amd64")
		pkgs+=(nvidia-cuda-dev)
		;;
	esac
	if [[ $CI_TARGET_ARCH != "x86" ]]; then
		pkgs+=(glusterfs-common)
	fi
	# Architecture-independent packages and packages for which we don't
	# care about the architecture.
	pkgs+=(
	    bison
	    flex
	    python3
	    python3-scipy
	    python3-six
	)
	sudo apt-get -qq update
	sudo apt-get install --no-install-recommends -qq -y "${pkgs[@]}"
	;;
    "osx")
	brew update >/dev/null 2>&1
	brew install cunit
	pip3 install scipy six
	;;
esac

echo "Python3 path: $(type -p python3 2>&1)"
echo "Python3 version: $(python3 -V 2>&1)"
