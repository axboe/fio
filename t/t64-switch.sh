#!/usr/bin/env bash
#
# Make sure that Fio actually does switch to the tausworthe64 random generator
# when it detects that the combination of block size and file size exceeds the
# limits of the default 32-bit random generator.
#
# Do this by counting the number of times offsets occurring more than once are
# touched. The default random generator should produce more duplicate offsets
# than the tausworthe64 random generator.
#
# Count offsets by parsing Fio's debug output. Use grep and cut to obtain a
# list of offsets, sort them, and count how many times offsets ocurring more
# than once are touched.
#
# Calculate the ratio of tausworthe32 duplicates to tausworthe64 duplicates. I
# am arbitrarily using a minimum ratio of 10 as the criteria for a passing
# test.
#
# Usage:
# t64-switch [FIO [COUNT]]
#

FIO=${1:-fio}
COUNT=${2:-1000000}

t32=$(${FIO} --name=test --ioengine=null --filesize=1T --bs=1 --rw=randread --debug=io --number_ios=${COUNT} --norandommap --randrepeat=0 --random_generator=tausworthe | grep complete: | cut -d '=' -f 2 | cut -d ',' -f 1 | sort -g | uniq -D | wc -l | tr -d ' ')
t64=$(${FIO} --name=test --ioengine=null --filesize=1T --bs=1 --rw=randread --debug=io --number_ios=${COUNT} --norandommap --randrepeat=0 | grep complete: | cut -d '=' -f 2 | cut -d ',' -f 1 | sort -g | uniq -D | wc -l | tr -d ' ')
if [ $t64 -gt 0 ]; then
	let ratio=$t32/$t64
else
	let ratio=$t32
fi

echo tausworthe32: $t32
echo tausworthe62: $t64
echo ratio: $ratio

if [ $ratio -ge 10 ]; then
	echo result: pass
else
	echo result: fail
	exit 1
fi
