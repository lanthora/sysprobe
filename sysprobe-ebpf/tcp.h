// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_TCP_H
#define SYSPROBE_EBPF_TCP_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/vmlinux.h"

static const int AF_INET = 2;
static const int AF_INET6 = 10;

static int trace_ipv4_tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	struct in_addr *saddr = &((struct sockaddr_in *)&ctx->saddr)->sin_addr;
	struct in_addr *daddr = &((struct sockaddr_in *)&ctx->daddr)->sin_addr;
	LOG("tcp_probe: saddr=%pI4:%u daddr=%pI4:%u srtt=%d", saddr, ctx->sport, daddr, ctx->dport, ctx->srtt);
	return 0;
}

static int trace_ipv6_tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	struct in6_addr *saddr = &((struct sockaddr_in6 *)&ctx->saddr)->sin6_addr;
	struct in6_addr *daddr = &((struct sockaddr_in6 *)&ctx->daddr)->sin6_addr;
	LOG("tcp_probe: saddr=[%pI6]:%u daddr=[%pI6]:%u srtt=%d", saddr, ctx->sport, daddr, ctx->dport, ctx->srtt);
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

static int trace_tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
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
