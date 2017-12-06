#!/bin/bash
# get student id from parameter
d=$1

testdir=auto

if [ -d "$d" ]; then

	mkdir $d/dophase1 > /dev/null 2>&1
	mkdir $d/dophase2 > /dev/null 2>&1
	cp $d/mymemory.c $d/*.h $d/dophase1
	cp $d/mymemory_opt.c $d/*.h $d/dophase2

    # Need to run tests once for mymemory.c and once for mymemory_opt.c


    # Remove any old log files.
    rm $d/dophase1/log/*.log > /dev/null 2>&1 ||:
    rm $d/dophase2/log/*.log > /dev/null 2>&1 ||:

    # Copy in the tester source and header files, and Makefile.
    cp $testdir/test_*.c $testdir/test_*.h $testdir/Makefile $d/dophase1
    cp $testdir/test_*.c $testdir/test_*.h $testdir/Makefile $d/dophase2
fi
