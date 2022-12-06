// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_TCP_H
#define SYSPROBE_EBPF_TCP_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/vmlinux.h"

static const int AF_INET = 2;
static const int AF_INET6 = 10;

static bool update_srtt_statistics(struct trace_event_raw_tcp_probe *ctx, struct tcp_probe_value *updated)
{
	static const long NS_PER_SEC = 1000000000L;
	u64 now = bpf_ktime_get_boot_ns();

	struct tcp_probe_key key = { .sock_cookie = ctx->sock_cookie };
	struct tcp_probe_value *value = bpf_map_lookup_elem(&tcp_probe_map, &key);
	if (value) {
		updated->last_submit_timestamp = value->last_submit_timestamp;
		updated->srtt_max = ctx->srtt > value->srtt_max ? ctx->srtt : value->srtt_max;
		updated->srtt_min = ctx->srtt < value->srtt_min ? ctx->srtt : value->srtt_min;
		updated->srtt_sum = ctx->srtt + value->srtt_sum;
		updated->srtt_count = value->srtt_count + 1;
	} else {
		updated->last_submit_timestamp = now;
		updated->srtt_max = ctx->srtt;
		updated->srtt_min = ctx->srtt;
		updated->srtt_sum = ctx->srtt;
		updated->srtt_count = 1;
	}

	if (updated->last_submit_timestamp + NS_PER_SEC < now) {
		bpf_map_delete_elem(&tcp_probe_map, &key);
		return true;
	} else {
		bpf_map_update_elem(&tcp_probe_map, &key, updated, BPF_ANY);
		return false;
	}
}

static int trace_ipv4_tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	struct tcp_probe_value value;
	if (!update_srtt_statistics(ctx, &value))
		return 0;

	u64 max = value.srtt_max;
	u64 min = value.srtt_min;
	u64 avg = value.srtt_sum / value.srtt_count;

	struct in_addr *saddr = &((struct sockaddr_in *)&ctx->saddr)->sin_addr;
	struct in_addr *daddr = &((struct sockaddr_in *)&ctx->daddr)->sin_addr;

	LOG("tcp_probe: saddr=%pI4:%u daddr=%pI4:%u srtt=(%u,%u,%u)", saddr, ctx->sport, daddr, ctx->dport, min, avg, max);
	return 0;
}

static int trace_ipv6_tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	struct tcp_probe_value value;
	if (!update_srtt_statistics(ctx, &value))
		return 0;

	u64 max = value.srtt_max;
	u64 min = value.srtt_min;
	u64 avg = value.srtt_sum / value.srtt_count;

	struct in6_addr *saddr = &((struct sockaddr_in6 *)&ctx->saddr)->sin6_addr;
	struct in6_addr *daddr = &((struct sockaddr_in6 *)&ctx->daddr)->sin6_addr;
	LOG("tcp_probe: saddr=[%pI6]:%u daddr=[%pI6]:%u srtt=(%u,%u,%u)", saddr, ctx->sport, daddr, ctx->dport, min, avg, max);
	return 0;
}

static int trace_tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = (struct global_cfg *)bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->tcp_probe_enabled)
		return 0;

	switch (ctx->family) {
	case AF_INET:
		trace_ipv4_tcp_probe(ctx);
		break;
	case AF_INET6:
		trace_ipv6_tcp_probe(ctx);
		break;
	default:
		break;
	}

	return 0;
}

static bool final_srtt_statistics(struct trace_event_raw_tcp_event_sk *ctx, struct tcp_probe_value *updated)
{
	struct tcp_probe_key key = { .sock_cookie = ctx->sock_cookie };
	struct tcp_probe_value *value = bpf_map_lookup_elem(&tcp_probe_map, &key);
	if (!value)
		return false;

	updated->last_submit_timestamp = value->last_submit_timestamp;
	updated->srtt_count = value->srtt_count;
	updated->srtt_max = value->srtt_max;
	updated->srtt_min = value->srtt_min;
	updated->srtt_sum = value->srtt_sum;
	bpf_map_delete_elem(&tcp_probe_map, &key);
	return true;
}

static int trace_tcp_destroy_sock(struct trace_event_raw_tcp_event_sk *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = (struct global_cfg *)bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->tcp_probe_enabled)
		return 0;

	struct tcp_probe_value value;
	u64 min = 0, avg = 0, max = 0;
	if (final_srtt_statistics(ctx, &value)) {
		max = value.srtt_max;
		min = value.srtt_min;
		avg = value.srtt_sum / value.srtt_count;
	}

	switch (ctx->family) {
	case AF_INET:
		LOG("tcp_destroy_sock: saddr=%pI4:%u daddr=%pI4:%u srtt=(%u,%u,%u)", &ctx->saddr, ctx->sport, &ctx->daddr, ctx->dport, min, avg, max);
		break;
	case AF_INET6:
		LOG("tcp_destroy_sock: saddr=[%pI6]:%u daddr=[%pI6]:%u srtt=(%u,%u,%u)", &ctx->saddr_v6, ctx->sport, &ctx->daddr_v6, ctx->dport, min,
		    avg, max);
		break;
	default:
		break;
	}

	return 0;
}

static int trace_tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = (struct global_cfg *)bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->tcp_probe_enabled)
		return 0;

	switch (ctx->family) {
	case AF_INET:
		LOG("tcp_retransmit_skb: saddr=%pI4.%u daddr=%pI4.%u", &ctx->saddr, ctx->sport, &ctx->daddr, ctx->dport);
		break;
	case AF_INET6:
		LOG("tcp_retransmit_skb: saddr=%pI6.%u daddr=%pI6.%u", &ctx->saddr_v6, ctx->sport, &ctx->daddr_v6, ctx->dport);
		break;
	default:
		break;
	}
	return 0;
}

static int trace_tcp_retransmit_synack(struct trace_event_raw_tcp_retransmit_synack *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = (struct global_cfg *)bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->tcp_probe_enabled)
		return 0;

	switch (ctx->family) {
	case AF_INET:
		LOG("tcp_retransmit_synack: saddr=%pI4:%u daddr=%pI4:%u", &ctx->saddr, ctx->sport, &ctx->daddr, ctx->dport);
		break;
	case AF_INET6:
		LOG("tcp_retransmit_synack: saddr=[%pI6]:%u daddr=[%pI6]:%u", &ctx->saddr_v6, ctx->sport, &ctx->daddr_v6, ctx->dport);
		break;
	default:
		break;
	}
	return 0;
}

static int trace_tcp_send_reset(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = (struct global_cfg *)bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->tcp_probe_enabled)
		return 0;

	switch (ctx->family) {
	case AF_INET:
		LOG("tcp_send_reset: saddr=%pI4:%u daddr=%pI4:%u", &ctx->saddr, ctx->sport, &ctx->daddr, ctx->dport);
		break;
	case AF_INET6:
		LOG("tcp_send_reset: saddr=[%pI6]:%u daddr=[%pI6]:%u", &ctx->saddr_v6, ctx->sport, &ctx->daddr_v6, ctx->dport);
		break;
	default:
		break;
	}
	return 0;
}

static int trace_tcp_receive_reset(struct trace_event_raw_tcp_event_sk *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = (struct global_cfg *)bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->tcp_probe_enabled)
		return 0;

	switch (ctx->family) {
	case AF_INET:
		LOG("tcp_receive_reset: saddr=%pI4:%u daddr=%pI4:%u", &ctx->saddr, ctx->sport, &ctx->daddr, ctx->dport);
		break;
	case AF_INET6:
		LOG("tcp_receive_reset: saddr=[%pI6]:%u daddr=[%pI6]:%u", &ctx->saddr_v6, ctx->sport, &ctx->daddr_v6, ctx->dport);
		break;
	default:
		break;
	}
	return 0;
}

#endif
