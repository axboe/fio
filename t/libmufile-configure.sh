#!/bin/sh
#
# Verify that an explicit libmufile configure request fails cleanly when the
# pkg-config metadata is unavailable.
#

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/fio-libmufile-configure.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' INT QUIT TERM

mkdir "$tmp/empty-pkgconfig"
# Configure supports out-of-tree invocation; never touch the caller's build.
cd "$tmp"
if env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
	-u CFLAGS -u CPPFLAGS -u LDFLAGS \
	PKG_CONFIG_PATH="$tmp/empty-pkgconfig" \
	PKG_CONFIG_LIBDIR="$tmp/empty-pkgconfig" \
	"$root/configure" --enable-libmufile >"$tmp/configure.log" 2>&1; then
	echo "configure unexpectedly enabled libmufile without pkg-config metadata" >&2
	exit 1
fi
grep -q "ERROR: User requested feature libmufile" \
	"$tmp/configure.log"
grep -q "pkg-config metadata" "$tmp/configure.log"
