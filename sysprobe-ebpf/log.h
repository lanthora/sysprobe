// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_LOG_H
#define SYSPROBE_EBPF_LOG_H

#include "sysprobe-common/types.h"
#include "sysprobe-ebpf/maps.h"
#include "sysprobe-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define ___LOG(__fmt, __args...)                                                                                                                     \
	{                                                                                                                                            \
		struct elog *__e = (struct elog *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct elog), 0);                                             \
		if (__e) {                                                                                                                           \
			__e->type = RB_EVENT_LOG;                                                                                                    \
			__e->nsec = bpf_ktime_get_boot_ns();                                                                                         \
			int len = BPF_SNPRINTF(__e->msg, CONFIG_LOG_LEN_MAX, __fmt, __args);                                                         \
			if (len > 0) {                                                                                                               \
				bpf_ringbuf_submit(__e, 0);                                                                                          \
			} else {                                                                                                                     \
				bpf_ringbuf_discard(__e, 0);                                                                                         \
			}                                                                                                                            \
		}                                                                                                                                    \
	}

#define __LOG(__fmt, __args...)                                                                                                                      \
	{                                                                                                                                            \
		int __zero = 0;                                                                                                                      \
		struct global_cfg *__cfg = bpf_map_lookup_elem(&global_cfg_map, &__zero);                                                            \
		if (__cfg && __cfg->log_enabled) {                                                                                                   \
			___LOG(__fmt, __args);                                                                                                       \
		}                                                                                                                                    \
	}

#define LOG __LOG

#endif
