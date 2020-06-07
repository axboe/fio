#!/bin/bash

case "$TRAVIS_OS_NAME" in
    "linux")
	# Architecture-dependent packages.
	pkgs=(
	    libaio-dev
	    libcunit1
	    libcunit1-dev
	    libgoogle-perftools4
	    libibverbs-dev
	    libiscsi-dev
	    libnuma-dev
	    librbd-dev
	    librdmacm-dev
	    libz-dev
	)
	if [[ "$BUILD_ARCH" == "x86" ]]; then
	    pkgs=("${pkgs[@]/%/:i386}")
	    pkgs+=(gcc-multilib)
	else
	    pkgs+=(glusterfs-common)
	fi
	# Architecture-independent packages and packages for which we don't
	# care about the architecture.
	pkgs+=(
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
	pip3 install scipy
	pip3 install six
	;;
esac

echo "Python version: $(/usr/bin/python -V 2>&1)"
echo "Python3 path: $(which python3 2>&1)"
echo "Python3 version: $(python3 -V 2>&1)"
