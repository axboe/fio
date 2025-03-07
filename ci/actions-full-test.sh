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
    skip=(
        6
	1007
	1008
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

    fi

    # If we are running a nightly test just run the verify tests.
    # Otherwise skip the verify test script because it takes so long.
    if [ "${GITHUB_EVENT_NAME}" == "schedule" ]; then
	args+=(
	    --run-only
	    1017
	)
    else
	skip+=(
	    1017
	)
    fi

    echo python3 t/run-fio-tests.py --skip "${skip[@]}" "${args[@]}"
    python3 t/run-fio-tests.py --skip "${skip[@]}" "${args[@]}"
    make -C doc html
}

main
