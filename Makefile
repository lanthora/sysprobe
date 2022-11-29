all: target/sysprobe

target/sysprobe: sysprobe/sysprobe.skel.h sysprobe/* sysprobe-common/*
	clang++ -g -O2 -I . -lbpf sysprobe/*.cc -o target/sysprobe

sysprobe/sysprobe.skel.h: sysprobe-ebpf/vmlinux.h sysprobe-ebpf/* sysprobe-common/*
	clang -D__TARGET_ARCH_x86 -g -O2 -I . -target bpf -c  sysprobe-ebpf/sysprobe.c -o target/sysprobe.o
	bpftool gen skeleton target/sysprobe.o > sysprobe/sysprobe.skel.h

sysprobe-ebpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > sysprobe-ebpf/vmlinux.h

clean:
	rm -f sysprobe-ebpf/vmlinux.h sysprobe/sysprobe.skel.h target/*

.PHONY: all clean
