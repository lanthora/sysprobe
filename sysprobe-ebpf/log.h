// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_LOG_H
#define SYSPROBE_EBPF_LOG_H

#include "sysprobe-common/types.h"
#include "sysprobe-ebpf/maps.h"
#include "sysprobe-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define LOG__(fmt, args...)                                                                                            \
	{                                                                                                              \
		struct elog *e__ = (struct elog *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct elog), 0);               \
		if (e__) {                                                                                             \
			e__->type = RB_EVENT_LOG;                                                                      \
			e__->nsec = bpf_ktime_get_boot_ns();                                                           \
			int len = BPF_SNPRINTF(e__->msg, CONFIG_LOG_LEN_MAX, fmt, args);                               \
			if (len > 0) {                                                                                 \
				bpf_ringbuf_submit(e__, 0);                                                            \
			} else {                                                                                       \
				bpf_ringbuf_discard(e__, 0);                                                           \
			}                                                                                              \
		}                                                                                                      \
	}
#endif

#define LOG(fmt, args...)                                                                                              \
	{                                                                                                              \
		int k0__ = 0;                                                                                          \
		struct global_cfg *cfg__ = (struct global_cfg *)bpf_map_lookup_elem(&global_cfg_map, &k0__);           \
		if (cfg__ && cfg__->log_enabled) {                                                                     \
			LOG__(fmt, args);                                                                              \
		}                                                                                                      \
	}
