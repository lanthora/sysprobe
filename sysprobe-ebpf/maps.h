// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_MAPS_H
#define SYSPROBE_EBPF_MAPS_H

#include "sysprobe-common/config.h"
#include "sysprobe-common/types.h"
#include "sysprobe-ebpf/types.h"
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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct global_cfg);
} global_cfg_map SEC(".maps");

// 在两个 hook 点之间传递数据
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CONFIG_CONCURRENT_THREAD_MAX);
	__type(key, struct hook_ctx_key);
	__type(value, struct hook_ctx_value);
} hook_ctx_map SEC(".maps");

#endif
