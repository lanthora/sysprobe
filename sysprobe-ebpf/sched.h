// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_SCHED_H
#define SYSPROBE_EBPF_SCHED_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/maps.h"

static int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (cfg && cfg->sched_disabled)
		return 0;

#if defined(DEBUG)
	pid_t parent_pid = ctx->parent_pid;
	pid_t child_pid = ctx->child_pid;

	LOG("sched_process_fork: parent_pid=%d child_pid=%d", parent_pid, child_pid);
#endif

	struct event_sched *e = (struct event_sched *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct event_stack_trace), 0);
	if (e) {
		e->type = RB_EVENT_SCHED;
		e->op = 0;
		e->pid = ctx->child_pid;
		e->ppid = ctx->parent_pid;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

static int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (cfg && cfg->sched_disabled)
		return 0;

#if defined(DEBUG)
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	unsigned int inum = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	unsigned int loc = ctx->__data_loc_filename & 0xFFFF;
	LOG("sched_process_exec: pid=%d mnt_ns=%u filename=%s", ctx->pid, inum, (void *)ctx + loc);
#endif

	struct event_sched *e = (struct event_sched *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct event_stack_trace), 0);
	if (e) {
		e->type = RB_EVENT_SCHED;
		e->op = 1;
		e->pid = ctx->pid;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

static int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (cfg && cfg->sched_disabled)
		return 0;

	int pid = ctx->pid;

#if defined(DEBUG)
	LOG("sched_process_exit: pid=%d", pid);
#endif

	bpf_map_delete_elem(&pproc_cfg_map, &pid);

	struct event_sched *e = (struct event_sched *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct event_stack_trace), 0);
	if (e) {
		e->type = RB_EVENT_SCHED;
		e->op = 2;
		e->pid = ctx->pid;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

#endif
