#!/bin/bash
# The PATH to appropriate distro commands must already be set before invoking
# this script
# The following environment variables must be set:
# PLATFORM={i686,x64}
# DISTRO={cygwin,msys2}
# The following environment can optionally be set:
# CYG_MIRROR=<URL>
set -eu

case "${ARCHITECTURE}" in
    "x64")
        PACKAGE_ARCH="x86_64"
        ;;
    "x86")
        PACKAGE_ARCH="i686"
        ;;
esac

echo "Installing packages..."
case "${DISTRO}" in
    "cygwin")
        CYG_MIRROR=${CYG_MIRROR:-"http://cygwin.mirror.constant.com"}
        setup-x86_64.exe --quiet-mode --no-shortcuts --only-site \
            --site "${CYG_MIRROR}" --packages \
            "mingw64-${PACKAGE_ARCH}-CUnit,mingw64-${PACKAGE_ARCH}-zlib"
        ;;
    "msys2")
        #pacman --noconfirm -Syuu # MSYS2 core update
        #pacman --noconfirm -Syuu # MSYS2 normal update
        pacman.exe --noconfirm -S \
            mingw-w64-${PACKAGE_ARCH}-clang \
            mingw-w64-${PACKAGE_ARCH}-cunit \
            mingw-w64-${PACKAGE_ARCH}-toolchain \
            mingw-w64-${PACKAGE_ARCH}-lld
        pacman.exe -Q # List installed packages
        ;;
esac

python.exe -m pip install scipy six

echo "Python3 path: $(type -p python3 2>&1)"
echo "Python3 version: $(python3 -V 2>&1)"
