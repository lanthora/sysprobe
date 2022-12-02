// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_TCP_H
#define SYSPROBE_EBPF_TCP_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/vmlinux.h"

static int trace_ipv4_tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	struct in_addr *saddr = &((struct sockaddr_in *)&ctx->saddr)->sin_addr;
	struct in_addr *daddr = &((struct sockaddr_in *)&ctx->daddr)->sin_addr;
	LOG("tcp_probe: saddr=%pI4.%u daddr=%pI4.%u srtt=%d", saddr, ctx->sport, daddr, ctx->dport, ctx->srtt);
	return 0;
}

static int trace_ipv6_tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	struct in6_addr *saddr = &((struct sockaddr_in6 *)&ctx->saddr)->sin6_addr;
	struct in6_addr *daddr = &((struct sockaddr_in6 *)&ctx->daddr)->sin6_addr;
	LOG("tcp_probe: saddr=%pI6.%u daddr=%pI6.%u srtt=%d", saddr, ctx->sport, daddr, ctx->dport, ctx->srtt);
	return 0;
}

static int trace_tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = (struct global_cfg *)bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->tcp_probe_enabled)
		return 0;

	static const int AF_INET = 2;
	static const int AF_INET6 = 10;

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

#endif
