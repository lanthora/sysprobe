all: target/sysprobe target/sockops.o

target/sysprobe: sysprobe/sysprobe.skel.h sysprobe/* sysprobe-common/* sysprobe-library/*
	g++ -std=c++20 -g -O2 -I . sysprobe/*.cc sysprobe-library/*.cc -lbpf -lbfd -lprocps -o target/sysprobe

sysprobe/sysprobe.skel.h: target/sysprobe.o
	bpftool gen skeleton target/sysprobe.o > sysprobe/sysprobe.skel.h

target/sysprobe.o: sysprobe-ebpf/vmlinux.h sysprobe-ebpf/*.h sysprobe-ebpf/sysprobe.c sysprobe-common/*
	clang -D__TARGET_ARCH_x86 -g -O2 -I . -target bpf -c sysprobe-ebpf/sysprobe.c -o target/sysprobe.o

target/sockops.o: sysprobe-ebpf/vmlinux.h sysprobe-ebpf/sockops.c
	clang -g -O2 -I . -target bpf -c sysprobe-ebpf/sockops.c -o target/sockops.o

sysprobe-ebpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > sysprobe-ebpf/vmlinux.h

clean:
	rm -f sysprobe-ebpf/vmlinux.h sysprobe/sysprobe.skel.h target/*

test:
	g++ -std=c++20 -g -O2 -I . sysprobe-test/addr2line-test.cc sysprobe-library/*.cc -lbfd -lprocps -o target/addr2line-test
	target/addr2line-test

install-sockops: target/sockops.o
	bpftool prog load ./target/sockops.o /sys/fs/bpf/sockops type sockops
	bpftool cgroup attach /sys/fs/cgroup sock_ops pinned /sys/fs/bpf/sockops
	bpftool prog show pinned /sys/fs/bpf/sockops

uninstall-sockops:
	bpftool cgroup detach /sys/fs/cgroup sock_ops pinned /sys/fs/bpf/sockops
	rm /sys/fs/bpf/sockops

printk:
	cat /sys/kernel/debug/tracing/trace_pipe

.PHONY: all clean test install-sockops uninstall-sockops printk
