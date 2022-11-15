#include "log.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	int ppid = BPF_CORE_READ(task, real_parent, tgid);
	DBG("handle_exec: ppid=%d", ppid);
	return 0;
}