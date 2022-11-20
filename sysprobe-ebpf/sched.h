// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_SCHED_H
#define SYSPROBE_EBPF_SCHED_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/maps.h"

static int try_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	pid_t parent_pid = ctx->parent_pid;
	pid_t child_pid = ctx->child_pid;
	LOG("fork: parent=%d, child=%d", parent_pid, child_pid);

	struct eproc *e = (struct eproc *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct eproc), 0);
	if (e) {
		e->type = RB_EVENT_PROC;
		e->nsec = bpf_ktime_get_boot_ns();
		e->tracepoint = 1;
		e->parent_pid = parent_pid;
		e->child_pid = child_pid;
		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}

static int try_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	int pid = ctx->pid;
	LOG("exit: pid=%d", pid);

	struct eproc *e = (struct eproc *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct eproc), 0);
	if (e) {
		e->type = RB_EVENT_PROC;
		e->nsec = bpf_ktime_get_boot_ns();
		e->tracepoint = 2;
		e->pid = pid;
		bpf_ringbuf_submit(e, 0);
	}
	bpf_map_delete_elem(&pproc_cfg_map, &pid);
	return 0;
}

#endif
