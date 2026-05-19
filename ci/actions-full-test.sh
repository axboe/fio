#!/bin/bash
# This script expects to be invoked from the base fio directory.
set -eu

main() {
    case "${CI_TARGET_BUILD}" in
	android*)
	    return 0;;
    esac

    echo "Running long running tests..."
    export PYTHONUNBUFFERED="TRUE"
    # We can't load modules so skip 1018 which requires null_blk
    skip=(
        6
	1007
	1008
	1018
    )
    args=(
        --debug
    )
    if [ "${GITHUB_JOB}" == "build-containers" ]; then
        # io_uring is disabled in containers
        # so skip the io_uring test
        skip+=(
            18
        )
	# cmd priority does not work in containers
	# so skip the related latency test cases
	args+=(
	    -p
            "1010:--skip 15 16 17 18 19 20 21 22"
        )
	# io_uring is unavailable in containers; use psync and libaio instead
	args+=(
	    -p
	    "1021:--ioengines psync,libaio"
	)

    fi

    echo python3 t/run-fio-tests.py --skip "${skip[@]}" "${args[@]}"
    python3 t/run-fio-tests.py -c --skip "${skip[@]}" "${args[@]}"
    make -C doc html
}

main
