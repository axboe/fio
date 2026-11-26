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

# Generated here so examples/ can change on their own. numjobs is 16, so free
# space must cover 16 times this per-thread size. filename_format omits
# $jobname: read reuses write's files, and both paths share those names.
size="${LIBMUFILE_SMOKE_SIZE:-1G}"

make_job() {
	cat >"$FIO_DIR/libmufile-$1.fio" <<EOF
[global]
ioengine=libmufile
directory=$FIO_DIR
gpu_dev_ids=$GPU_DEV_IDS
musa_io=$1
direct=1
bs=1m
size=$size
numjobs=16
thread
filename_format=job.\$jobnum.\$filenum
verify_state_save=0

[write]
rw=write

[read]
rw=read

[verify]
rw=write
verify=md5

[randverify]
rw=randwrite
size=16m
verify=md5
EOF
}

run_section() {
	"$fio" --section="$1" "$FIO_DIR/libmufile-$2.fio"
}

for path in mufile posix; do
	make_job "$path"
	run_section write "$path"
	run_section read "$path"
	run_section verify "$path"
done
run_section randverify mufile
