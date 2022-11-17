// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_LOG_H
#define SYSPROBE_EBPF_LOG_H

#include "sysprobe-common/types.h"
#include "sysprobe-ebpf/maps.h"
#include "sysprobe-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define LOG(fmt, args...)                                                                                              \
	{                                                                                                              \
		struct elog *e;                                                                                        \
		e = (struct elog *)bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);                                       \
		if (e) {                                                                                               \
			e->type = RB_EVENT_LOG;                                                                        \
			e->nsec = bpf_ktime_get_boot_ns();                                                             \
			int len = BPF_SNPRINTF(e->msg, CONFIG_LOG_LEN_MAX, fmt, args);                                 \
			if (len > 0) {                                                                                 \
				bpf_ringbuf_submit(e, 0);                                                              \
			} else {                                                                                       \
				bpf_ringbuf_discard(e, 0);                                                             \
			}                                                                                              \
		}                                                                                                      \
	}
#endif
