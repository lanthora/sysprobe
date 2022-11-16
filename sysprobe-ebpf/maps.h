#ifndef SYSPROBE_EBPF_MAPS_H
#define SYSPROBE_EBPF_MAPS_H

#include "sysprobe-ebpf/vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

#endif
