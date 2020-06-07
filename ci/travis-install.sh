#!/bin/bash

case "$TRAVIS_OS_NAME" in
    "linux")
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
	    pkgs+=(gcc-multilib python3-scipy)
	else
	    pkgs+=(glusterfs-common python3-scipy)
	fi
	sudo apt-get -qq update
	sudo apt-get install --no-install-recommends -qq -y "${pkgs[@]}"
	;;
    "osx")
	brew update
	brew install cunit
	pip3 install scipy
	;;
esac
