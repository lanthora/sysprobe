// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_KPROBE_H
#define SYSPROBE_EBPF_KPROBE_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/skb.h"
#include "sysprobe-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static int trace_enter_nf_hook_slow(struct sk_buff *skb)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->nf_hook_slow_enabled)
		return 0;

	struct hook_ctx_key key = { .func = FUNC_KP_NF_HOOK_SLOW };
	struct hook_ctx_value value = { .skb = skb };

	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);

	return 0;
}

static int trace_exit_nf_hook_slow(int ret)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->nf_hook_slow_enabled)
		return 0;

	struct hook_ctx_key key = { .func = FUNC_KP_NF_HOOK_SLOW };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	static const int EPERM = 1;

	if (value && value->skb && ret == -EPERM) {
		struct iphdr *iph = ip_hdr(value->skb);
		u8 protocol = BPF_CORE_READ(iph, protocol);

		if (protocol != IPPROTO_ICMP && protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
			return 0;

		u32 saddr = BPF_CORE_READ(iph, saddr);
		u32 daddr = BPF_CORE_READ(iph, daddr);

		LOG("nf_hook_slow: protocol=%u saddr=%pI4 daddr=%pI4", protocol, &saddr, &daddr);
	}

	bpf_map_delete_elem(&hook_ctx_map, &key);

	return 0;
}

#endif
