// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_TCP_H
#define SYSPROBE_EBPF_TCP_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/vmlinux.h"

static int trace_tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	LOG("tcp_probe: srtt=%d", ctx->srtt);
	return 0;
}

#endif
