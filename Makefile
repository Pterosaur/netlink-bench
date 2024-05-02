KERNEL_DIR=/usr/src/kernel-headers-$(shell uname -r)
obj-m += nl_bench_ko.o
ccflags-y := -Wno-declaration-after-statement

all: bench-cli bench-ko

bench-cli:
	g++ nl_bench.cpp -o ./output/nl_bench

bench-ko:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

test: test-prepare test-run test-cleanup

test-prepare:
	# Load kernel module
	sudo insmod nl_bench_ko.ko

test-run:
	# Test 10 message with 1MB data for 100 rounds - 1GB data in total
	./output/nl_bench 10 1048576 100

test-cleanup:
	# Unload kernel module
	sudo rmmod nl_bench_ko.ko