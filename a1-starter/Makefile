KDIR=/lib/modules/`uname -r`/build

kbuild:
	make -C $(KDIR) M=`pwd`

test:
	gcc -o test_intercept test_intercept.c

clean:
	make -C $(KDIR) M=`pwd` clean
