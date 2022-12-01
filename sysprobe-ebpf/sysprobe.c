// SPDX-License-Identifier: GPL-2.0-only
#include "sysprobe-ebpf/kprobe.h"
#include "sysprobe-ebpf/sched.h"
#include "sysprobe-ebpf/skb.h"
#include "sysprobe-ebpf/syscalls.h"
#include "sysprobe-ebpf/vmlinux.h"
#include <asm/unistd.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tp/sched/sched_process_fork")
int sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	return trace_sched_process_fork(ctx);
}

SEC("tp/sched/sched_process_exit")
int sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	return trace_sched_process_exit(ctx);
}

SEC("tp/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	switch (ctx->id) {
	case __NR_read:
		trace_sys_enter_read(ctx);
		break;
	case __NR_write:
		trace_sys_enter_write(ctx);
		break;
	case __NR_futex:
		trace_sys_enter_futex(ctx);
		break;
	case __NR_futex_waitv:
		trace_sys_enter_futex_waitv(ctx);
		break;
	}
	return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	switch (ctx->id) {
	case __NR_read:
		trace_sys_exit_read(ctx);
		break;
	case __NR_write:
		trace_sys_exit_write(ctx);
		break;
	case __NR_futex:
		trace_sys_exit_futex(ctx);
		break;
	case __NR_futex_waitv:
		trace_sys_exit_futex_waitv(ctx);
		break;
	}
	return 0;
}

// https://github.com/torvalds/linux/commit/c504e5c2f9648a1e5c2be01e8c3f59d394192bd3
SEC("tp/skb/kfree_skb")
int kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
	return trace_kfree_skb(ctx);
}

SEC("kprobe/nf_hook_slow")
int BPF_KPROBE(enter_nf_hook_slow, struct sk_buff *skb, struct nf_hook_state *state, const struct nf_hook_entries *e,
	       unsigned int i)
{
	return trace_enter_nf_hook_slow(skb);
}

SEC("kretprobe/nf_hook_slow")
int BPF_KRETPROBE(exit_nf_hook_slow, int ret)
{
	return trace_exit_nf_hook_slow(ret);
}
