#!/bin/bash
#
# Do some basic test of the --readonly parameter
#
# DUT should be a device that accepts read, write, and trim operations
#
# Example usage:
#
# DUT=/dev/fioa t/readonly.sh
#
TESTNUM=1

#
# The first parameter is the return code
# The second parameter is 0        if the return code should be 0
#                         positive if the return code should be positive
#
check () {
	echo "********************"

	if [ $2 -gt 0 ]; then
		if [ $1 -eq 0 ]; then
			echo "Test $TESTNUM failed"
			echo "********************"
			exit 1
		else
			echo "Test $TESTNUM passed"
		fi
	else
		if [ $1 -gt 0 ]; then
			echo "Test $TESTNUM failed"
			echo "********************"
			exit 1
		else
			echo "Test $TESTNUM passed"
		fi
	fi

	echo "********************"
	echo
	TESTNUM=$((TESTNUM+1))
}

./fio --name=test --filename=$DUT --rw=randread  --readonly --time_based --runtime=1s &> /dev/null
check $? 0
./fio --name=test --filename=$DUT --rw=randwrite --readonly --time_based --runtime=1s &> /dev/null
check $? 1
./fio --name=test --filename=$DUT --rw=randtrim  --readonly --time_based --runtime=1s &> /dev/null
check $? 1

./fio --name=test --filename=$DUT --readonly --rw=randread  --time_based --runtime=1s &> /dev/null
check $? 0
./fio --name=test --filename=$DUT --readonly --rw=randwrite --time_based --runtime=1s &> /dev/null
check $? 1
./fio --name=test --filename=$DUT --readonly --rw=randtrim  --time_based --runtime=1s &> /dev/null
check $? 1

./fio --name=test --filename=$DUT --rw=randread  --time_based --runtime=1s &> /dev/null
check $? 0
./fio --name=test --filename=$DUT --rw=randwrite --time_based --runtime=1s &> /dev/null
check $? 0
./fio --name=test --filename=$DUT --rw=randtrim  --time_based --runtime=1s &> /dev/null
check $? 0

./fio t/jobs/readonly-r.fio --readonly &> /dev/null
check $? 0
./fio t/jobs/readonly-w.fio --readonly &> /dev/null
check $? 1
./fio t/jobs/readonly-t.fio --readonly &> /dev/null
check $? 1

./fio --readonly t/jobs/readonly-r.fio &> /dev/null
check $? 0
./fio --readonly t/jobs/readonly-w.fio &> /dev/null
check $? 1
./fio --readonly t/jobs/readonly-t.fio &> /dev/null
check $? 1

./fio t/jobs/readonly-r.fio &> /dev/null
check $? 0
./fio t/jobs/readonly-w.fio &> /dev/null
check $? 0
./fio t/jobs/readonly-t.fio &> /dev/null
check $? 0
