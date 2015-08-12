obj-m += sha_hash_test.o

PHONY: all

random:
	dd if=/dev/urandom of=random bs=4096 count=4096

build: random sha_hash_test.c
	make M=`pwd` -C /usr/src/kernels/`uname -r` modules

clean:
	make M=`pwd` -C /usr/src/kernels/`uname -r` clean
	rm -rf ./random ./testfile

test: build
	time ./test.sh

