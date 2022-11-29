// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_KPROBE_H
#define SYSPROBE_EBPF_KPROBE_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

int try_enter_kfree_skb_reason(struct sk_buff *skb, enum skb_drop_reason reason)
{
	LOG("kfree_skb_reason(%p, %d)", (u64)skb, reason);
	return 0;
}

int try_exit_kfree_skb_reason()
{
	return 0;
}

#endif
