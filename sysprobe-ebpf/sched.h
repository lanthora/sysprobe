#ifndef SYSPROBE_EBPF_SCHED_H
#define SYSPROBE_EBPF_SCHED_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/maps.h"

static int try_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	pid_t parent_pid = ctx->parent_pid;
	pid_t child_pid = ctx->child_pid;
	LOG("fork: parent=%d, child=%d", parent_pid, child_pid);
	return 0;
}

static int try_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	int pid = ctx->pid;
	LOG("exit: pid=%d", pid);
	bpf_map_delete_elem(&pproc_cfg_map, &pid);
	return 0;
}

#endif
