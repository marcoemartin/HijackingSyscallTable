#!/bin/bash
d=$1
testdir=auto
echo "$d/dophase1/a.out"
if [ -f "$d/dophase1/a.out" ]; then
    mkdir -p $d/dophase1/log/
    for t in $(find $testdir/traces -maxdepth 1 -type f); do
      trace="${t##*/}"
	  gdb -x $testdir/gdb_script --quiet --args $d/dophase1/a.out $t > $d/dophase1/log/$trace.log 2>&1

    done
else 
  	echo No exec
fi

echo "$d/dophase2/a.out"
if [ -f "$d/dophase2/a.out" ]; then
    mkdir -p $d/dophase2/log/
    for t in $(find $testdir/traces -maxdepth 1 -type f); do
      trace="${t##*/}"
	  gdb -x $testdir/gdb_script --quiet --args $d/dophase2/a.out $t > $d/dophase2/log/$trace.log 2>&1

    done
else 
  	echo No exec
fi
