// SPDX-License-Identifier: GPL-2.0-only
#include "sysprobe-ebpf/kprobe.h"
#include "sysprobe-ebpf/sched.h"
#include "sysprobe-ebpf/syscalls.h"
#include "sysprobe-ebpf/vmlinux.h"
#include <asm/unistd.h>

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

SEC("tp/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	switch (ctx->id) {
	case __NR_read:
		try_sys_enter_read(ctx);
		break;
	case __NR_write:
		try_sys_enter_write(ctx);
		break;
	case __NR_futex:
		try_sys_enter_futex(ctx);
		break;
	case __NR_futex_waitv:
		try_sys_enter_futex_waitv(ctx);
		break;
	}
	return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	switch (ctx->id) {
	case __NR_read:
		try_sys_exit_read(ctx);
		break;
	case __NR_write:
		try_sys_exit_write(ctx);
		break;
	case __NR_futex:
		try_sys_exit_futex(ctx);
		break;
	case __NR_futex_waitv:
		try_sys_exit_futex_waitv(ctx);
		break;
	}
	return 0;
}

SEC("kprobe/kfree_skb_reason")
int BPF_KPROBE(enter_kfree_skb_reason, struct sk_buff *skb, enum skb_drop_reason reason)
{
	return try_enter_kfree_skb_reason(skb, reason);
}

SEC("kretprobe/kfree_skb_reason")
int BPF_KRETPROBE(exit_kfree_skb_reason)
{
	return try_exit_kfree_skb_reason();
}
