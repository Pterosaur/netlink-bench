KERNEL_DIR=/usr/src/linux-headers-$(shell uname -r)
obj-m += nl_bench_ko.o
ccflags-y := -Wno-declaration-after-statement

all: bench-cli bench-ko

bench-cli:
	mkdir -p ./output
	g++ -O2 nl_bench.cpp -o ./output/nl_bench

bench-ko:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

test: test-prepare test-run test-cleanup

test-prepare:
	# Load kernel module
	sudo insmod nl_bench_ko.ko

test-run:
	# Test 1 message with 1MB data for 1000 rounds - 1GB data in total
	sudo ./output/nl_bench 1 1048576 1000 1 &
	sudo ./output/nl_bench 1 1048576 1000 0 > /dev/null


test-cleanup:
	# Unload kernel module
	sudo rmmod nl_bench_ko.ko