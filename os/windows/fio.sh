#!/bin/sh
/usr/sbin/cygserver > /dev/null &
/bin/real_fio $@
/usr/sbin/cygserver -S > /dev/null