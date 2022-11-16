target/sysprobe: sysprobe/sysprobe.skel.h sysprobe/* sysprobe-common/*
	clang++ -I . sysprobe/log.cc -lbpf -o target/sysprobe

sysprobe/sysprobe.skel.h: sysprobe-ebpf/vmlinux.h sysprobe-ebpf/* sysprobe-common/*
	clang -g -O2 -target bpf -I . -c  sysprobe-ebpf/sysprobe.c -o target/sysprobe.o
	bpftool gen skeleton target/sysprobe.o > sysprobe/sysprobe.skel.h

sysprobe-ebpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > sysprobe-ebpf/vmlinux.h

run: target/sysprobe
	@target/sysprobe

.PHONY: run
