#!/bin/bash
d=$1
testdir=auto

if [ -d "$d/dophase1" ]; then
    mkdir -p $d/dophase1/log/
    make -w -C $d/dophase1 clean all > $d/dophase1/make.log 2>&1
	mv $d/dophase1/make.log $d/dophase1/log/make.log
fi

if [ -d "$d/dophase2" ]; then
    mkdir -p $d/dophase2/log/
    make -w -C $d/dophase2 clean all > $d/dophase2/make.log 2>&1
	mv $d/dophase2/make.log $d/dophase2/log/make.log
fi
