#ifndef SYSPROBE_EBPF_SCHED_H
#define SYSPROBE_EBPF_SCHED_H

#include "sysprobe-ebpf/log.h"

static int try_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	LOG("fork: parent=%d, child=%d", ctx->parent_pid, ctx->child_pid);
	return 0;
}

#endif
