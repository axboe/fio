#!/bin/sh
set -eu

if ! ./fio --enghelp=libmufile >/dev/null 2>&1; then
	echo "SKIP libmufile engine is not built"
	exit 0
fi
if [ -z "${FIO_DIR:-}" ] || [ -z "${GPU_DEV_IDS:-}" ]; then
	echo "SKIP set FIO_DIR and GPU_DEV_IDS to run on hardware"
	exit 0
fi

./fio --section=write examples/libmufile-mufile.fio
./fio --section=read examples/libmufile-mufile.fio
./fio --section=write examples/libmufile-posix.fio
