#!/bin/sh
#
# Run the libmufile direct, POSIX, verify, and random workloads when hardware
# prerequisites are available. This is intentionally a manual hardware test.
#

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
fio="${FIO_BIN:-$root/fio}"

if ! "$fio" --enghelp=libmufile >/dev/null 2>&1; then
	echo "SKIP libmufile engine is not built"
	exit 0
fi
if [ -z "${FIO_DIR:-}" ] || [ -z "${GPU_DEV_IDS:-}" ]; then
	echo "SKIP set FIO_DIR and GPU_DEV_IDS to run on hardware"
	exit 0
fi

FIO_DIR=$(mktemp -d "$FIO_DIR/fio-libmufile.XXXXXX")
FIO_DIR=$(CDPATH= cd -- "$FIO_DIR" && pwd)
export FIO_DIR
trap 'rm -rf "$FIO_DIR"' EXIT
trap 'exit 1' INT QUIT TERM

# Match filenames across separate write/read sections, without sharing files
# between worker threads or leaving verify-state files in the source tree.
cd "$FIO_DIR"
run_section() {
	"$fio" --filename_format='job.$jobnum.$filenum' --verify_state_save=0 \
		--section="$1" "$root/examples/$2"
}

run_section write libmufile-mufile.fio
run_section read libmufile-mufile.fio
run_section verify libmufile-mufile.fio
run_section write libmufile-posix.fio
run_section read libmufile-posix.fio
run_section verify libmufile-posix.fio
run_section randverify libmufile-mufile.fio
