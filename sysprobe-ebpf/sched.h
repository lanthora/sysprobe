// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_SCHED_H
#define SYSPROBE_EBPF_SCHED_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/maps.h"

static int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->sched_enabled)
		return 0;

	pid_t parent_pid = ctx->parent_pid;
	pid_t child_pid = ctx->child_pid;

	LOG("sched_process_fork: parent_pid=%d child_pid=%d", parent_pid, child_pid);
	return 0;
}

static int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->sched_enabled)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	unsigned int inum = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	unsigned int loc = ctx->__data_loc_filename & 0xFFFF;
	LOG("sched_process_exec: pid=%d mnt_ns=%u filename=%s", ctx->pid, inum, (void *)ctx + loc);
	return 0;
}

static int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->sched_enabled)
		return 0;

	int pid = ctx->pid;
	LOG("sched_process_exit: pid=%d", pid);

	bpf_map_delete_elem(&pproc_cfg_map, &pid);
	return 0;
}

#endif
