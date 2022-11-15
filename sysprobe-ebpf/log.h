#ifndef SYSPROBE_EBPF_LOG_H
#define SYSPROBE_EBPF_LOG_H

#include "../sysprobe-common/log.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} log_ringbuf SEC(".maps");

#define DBG(fmt, args...)                                                                                              \
	{                                                                                                              \
		struct log_event *e;                                                                                   \
		e = bpf_ringbuf_reserve(&log_ringbuf, sizeof(*e), 0);                                                  \
		if (e) {                                                                                               \
			e->len = BPF_SNPRINTF(e->msg, LOG_LEN_MAX, fmt, args);                                         \
			if (e->len > 0 && e->len < LOG_LEN_MAX) {                                                      \
				bpf_ringbuf_submit(e, 0);                                                              \
			} else {                                                                                       \
				bpf_ringbuf_discard(e, 0);                                                             \
			}                                                                                              \
		}                                                                                                      \
	}

#endif
