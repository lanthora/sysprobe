// SPDX-License-Identifier: GPL-2.0-only
#include "sysprobe-ebpf/sched.h"
#include "sysprobe-ebpf/syscalls.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tp/sched/sched_process_fork")
int sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	return try_sched_process_fork(ctx);
}

SEC("tp/sched/sched_process_exit")
int sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	return try_sched_process_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	return try_sys_enter_read(ctx);
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	return try_sys_exit_read(ctx);
}

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	return try_sys_enter_write(ctx);
}

SEC("tracepoint/syscalls/sys_exit_write")
int sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	return try_sys_exit_write(ctx);
}
