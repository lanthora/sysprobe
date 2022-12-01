// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_TCP_H
#define SYSPROBE_EBPF_TCP_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/vmlinux.h"

static int trace_tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	static const int AF_INET = 2;
	static const int AF_INET6 = 10;
	static const int SRTT_THRESHOLD = 10000;

	if (ctx->srtt < SRTT_THRESHOLD)
		return 0;

	void *saddr, *daddr;

	switch (ctx->family) {
	case AF_INET:
		saddr = &((struct sockaddr_in *)&ctx->saddr)->sin_addr;
		daddr = &((struct sockaddr_in *)&ctx->daddr)->sin_addr;
		LOG("tcp_probe: src=%pI4.%u dst=%pI4.%u srtt=%d", saddr, ctx->sport, daddr, ctx->dport, ctx->srtt);
		break;
	case AF_INET6:
		saddr = &((struct sockaddr_in6 *)&ctx->saddr)->sin6_addr;
		daddr = &((struct sockaddr_in6 *)&ctx->daddr)->sin6_addr;
		LOG("tcp_probe: src=%pI6.%u dst=%pI6.%u srtt=%d", saddr, ctx->sport, daddr, ctx->dport, ctx->srtt);
		break;
	default:
		break;
	}

	return 0;
}

#endif
