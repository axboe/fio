#!/usr/bin/env bash

readonly BASEDIR=$(readlink -f $(dirname $0))/..
cd $BASEDIR

# exit on errors
set -e

if hash astyle; then
	echo -n "Checking coding style..."
	rm -f astyle.log
	touch astyle.log
	astyle --options=.astylerc "*.c" >> astyle.log
	astyle --options=.astylerc "*.h" >> astyle.log
	if grep -q "^Formatted" astyle.log; then
		echo " errors detected"
		git diff
		sed -i -e 's/  / /g' astyle.log
		grep --color=auto "^Formatted.*" astyle.log
		echo "Incorrect code style detected in one or more files."
		echo "The files have been automatically formatted."
		echo "Remember to add the files to your commit."
		rm -f astyle.log
		exit 1
	fi
	echo " OK"
	rm -f astyle.log
else
	echo "You do not have astyle installed so your code style is not being checked!"
	exit 0
fi

git grep -I -l -e . -z | \
	xargs -0 -P8 -n1 tools/eofnl

exit 0
