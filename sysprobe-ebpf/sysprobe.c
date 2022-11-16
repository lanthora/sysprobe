#include "sysprobe-ebpf/sched.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tp/sched/sched_process_fork")
int sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	return try_sched_process_fork(ctx);
}
