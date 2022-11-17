// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_SYSCALLS_H
#define SYSPROBE_EBPF_SYSCALLS_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/maps.h"

static int try_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	unsigned int fd = (unsigned int)ctx->args[0];
	char *buf = (char *)ctx->args[1];
	size_t count = (size_t)ctx->args[2];

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->io_event_socket_disabled) {
		// TODO: 检测是否为 socket 类型,处理后上报
	}

	if (cfg && cfg->io_event_others_enabled) {
		LOG("enter read: tgid=%d pid=%d fd=%d, buf=%p count=%d", tgid, pid, fd, buf, count);
	}

	return 0;
}

static int try_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	int ret = (int)ctx->ret;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);

	if (!cfg || !cfg->io_event_socket_disabled) {
		// TODO: 检测是否为 socket 类型,处理后上报
	}

	if (cfg && cfg->io_event_others_enabled) {
		LOG("exit read: tgid=%d pid=%d ret=%d", tgid, pid, ret);
	}

	return 0;
}

#endif
