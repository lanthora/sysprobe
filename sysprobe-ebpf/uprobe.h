// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_UPROBE_H
#define SYSPROBE_EBPF_UPROBE_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/skb.h"
#include "sysprobe-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static int trace_call_stack(struct pt_regs *ctx)
{
	u32 stackid = bpf_get_stackid(ctx, &stack_trace_map, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK);
	LOG("call_stack: stackid=%u", stackid);

	struct event_stack_trace *e = (struct event_stack_trace *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct event_stack_trace), 0);
	if (e) {
		e->type = RB_EVENT_STACK_TRACE;
		e->stackid = stackid;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

#endif
