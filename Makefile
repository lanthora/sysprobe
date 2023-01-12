all: target/sysprobe target/sockops.o

target/sysprobe: sysprobe/sysprobe.skel.h sysprobe/* sysprobe-common/* sysprobe-library/*
	g++ -std=c++20 -g -O2 -I . sysprobe/*.cc sysprobe-library/*.cc -lbpf -lbfd -lprocps -o target/sysprobe

sysprobe/sysprobe.skel.h: sysprobe-ebpf/vmlinux.h sysprobe-ebpf/* sysprobe-common/*
	clang -D__TARGET_ARCH_x86 -g -O2 -I . -target bpf -c sysprobe-ebpf/sysprobe.c -o target/sysprobe.o
	bpftool gen skeleton target/sysprobe.o > sysprobe/sysprobe.skel.h

target/sockops.o: sysprobe-ebpf/vmlinux.h sysprobe-ebpf/sockops.c
	clang -g -O2 -I . -target bpf -c sysprobe-ebpf/sockops.c -o target/sockops.o

sysprobe-ebpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > sysprobe-ebpf/vmlinux.h

clean:
	rm -f sysprobe-ebpf/vmlinux.h sysprobe/sysprobe.skel.h target/*

test:
	g++ -std=c++20 -g -O2 -I . sysprobe-test/addr2line-test.cc sysprobe-library/*.cc -lbfd -lprocps -o target/addr2line-test
	target/addr2line-test

.PHONY: all clean test
