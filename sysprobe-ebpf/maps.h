#ifndef SYSPROBE_EBPF_MAPS_H
#define SYSPROBE_EBPF_MAPS_H

#include "sysprobe-common/config.h"
#include "sysprobe-common/types.h"
#include "sysprobe-ebpf/vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, CONFIG_RINGBUF_SIZE_MAX);
} ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CONFIG_PROCESS_NUMBER_MAX);
	__type(key, int);
	__type(value, struct pproc_cfg);
} pproc_cfg_map SEC(".maps");

#endif
