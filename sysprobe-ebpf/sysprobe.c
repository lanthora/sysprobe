// SPDX-License-Identifier: GPL-2.0-only
#include "sysprobe-ebpf/kprobe.h"
#include "sysprobe-ebpf/sched.h"
#include "sysprobe-ebpf/skb.h"
#include "sysprobe-ebpf/syscalls.h"
#include "sysprobe-ebpf/tcp.h"
#include "sysprobe-ebpf/uprobe.h"
#include "sysprobe-ebpf/vmlinux.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tp/sched/sched_process_fork")
int sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	return trace_sched_process_fork(ctx);
}

SEC("tp/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	return trace_sched_process_exec(ctx);
}

SEC("tp/sched/sched_process_exit")
int sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	return trace_sched_process_exit(ctx);
}

SEC("tp/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	return trace_sys_enter(ctx);
}

SEC("tp/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	return trace_sys_exit(ctx);
}

SEC("tp/skb/kfree_skb")
int kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
	return trace_kfree_skb(ctx);
}

SEC("kprobe/nf_hook_slow")
int BPF_KPROBE(enter_nf_hook_slow, struct sk_buff *skb, struct nf_hook_state *state, const struct nf_hook_entries *e, unsigned int i)
{
	return trace_enter_nf_hook_slow(skb);
}

SEC("kretprobe/nf_hook_slow")
int BPF_KRETPROBE(exit_nf_hook_slow, int ret)
{
	return trace_exit_nf_hook_slow(ret);
}

SEC("tp/tcp/tcp_probe")
int tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	return trace_tcp_probe(ctx);
}

SEC("tp/tcp/tcp_retransmit_skb")
int tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	return trace_tcp_retransmit_skb(ctx);
}

SEC("tp/tcp/tcp_retransmit_synack")
int tcp_retransmit_synack(struct trace_event_raw_tcp_retransmit_synack *ctx)
{
	return trace_tcp_retransmit_synack(ctx);
}

SEC("tp/tcp/tcp_send_reset")
int tcp_send_reset(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	return trace_tcp_send_reset(ctx);
}

SEC("tp/tcp/tcp_receive_reset")
int tcp_receive_reset(struct trace_event_raw_tcp_event_sk *ctx)
{
	return trace_tcp_receive_reset(ctx);
}

SEC("tp/tcp/tcp_destroy_sock")
int tcp_destroy_sock(struct trace_event_raw_tcp_event_sk *ctx)
{
	return trace_tcp_destroy_sock(ctx);
}

SEC("uprobe")
int BPF_KPROBE(call_stack)
{
	return trace_call_stack(ctx);
}
