// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_SYSCALLS_H
#define SYSPROBE_EBPF_SYSCALLS_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/maps.h"
#include "sysprobe-ebpf/types.h"
#include "sysprobe-ebpf/vmlinux.h"

static umode_t fd_i_mode(unsigned int idx, void **private_data)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);

	unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
	if (idx > max_fds)
		return 0;

	struct file **fd = BPF_CORE_READ(fdt, fd);
	struct file *file;
	bpf_probe_read_kernel(&file, sizeof(file), fd + idx);

	*private_data = BPF_CORE_READ(file, private_data);
	if (!*private_data)
		return 0;

	umode_t i_mode = BPF_CORE_READ(file, f_inode, i_mode);
	return i_mode & S_IFMT;
}

static int try_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	unsigned int fd = (unsigned int)ctx->args[0];
	char *buf = (char *)ctx->args[1];
	size_t count = (size_t)ctx->args[2];

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);

	void *private_data;
	umode_t i_mode = fd_i_mode(fd, &private_data);

	switch (i_mode) {
	case S_IFSOCK:
		if (cfg && cfg->io_event_socket_enabled) {
			LOG("socket read enter: tgid=%d pid=%d fd=%d, buf=%p count=%d", tgid, pid, fd, buf, count);
			struct hook_ctx_key key = { .func = FUNC_SYSCALL_READ, .tgid = tgid, .pid = pid };
			struct hook_ctx_value value = { .buf = buf };
			bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);
			return 0;
		}
		break;
	default:
		if (cfg && cfg->io_event_others_enabled) {
			LOG("others read enter: tgid=%d pid=%d fd=%d, buf=%p count=%d", tgid, pid, fd, buf, count);
		}
		break;
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

	if (cfg && cfg->io_event_socket_enabled) {
		struct hook_ctx_key key = { .func = FUNC_SYSCALL_READ, .tgid = tgid, .pid = pid };
		struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);
		if (value) {
			char *buf = value->buf;
			LOG("socket read exit: tgid=%d pid=%d buf=%p ret=%d", tgid, pid, buf, ret);
			bpf_map_delete_elem(&hook_ctx_map, &key);
			return 0;
		}
	}

	if (cfg && cfg->io_event_others_enabled) {
		LOG("others read exit: tgid=%d pid=%d ret=%d", tgid, pid, ret);
	}

	return 0;
}

static int try_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	unsigned int fd = (unsigned int)ctx->args[0];
	char *buf = (char *)ctx->args[1];
	size_t count = (size_t)ctx->args[2];

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);

	void *private_data;
	umode_t i_mode = fd_i_mode(fd, &private_data);

	switch (i_mode) {
	case S_IFSOCK:
		if (cfg && cfg->io_event_socket_enabled) {
			LOG("socket write enter: tgid=%d pid=%d fd=%d, buf=%p count=%d", tgid, pid, fd, buf, count);
			struct hook_ctx_key key = { .func = FUNC_SYSCALL_WRITE, .tgid = tgid, .pid = pid };
			struct hook_ctx_value value = { .buf = buf };
			bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);
			return 0;
		}
	default:
		if (cfg && cfg->io_event_others_enabled) {
			LOG("others write enter: tgid=%d pid=%d fd=%d, buf=%p count=%d", tgid, pid, fd, buf, count);
		}
		break;
	}

	return 0;
}

static int try_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	int ret = (int)ctx->ret;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);

	if (cfg && cfg->io_event_socket_enabled) {
		struct hook_ctx_key key = { .func = FUNC_SYSCALL_WRITE, .tgid = tgid, .pid = pid };
		struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);
		if (value) {
			char *buf = value->buf;
			LOG("socket write exit: tgid=%d pid=%d buf=%p ret=%d", tgid, pid, buf, ret);
			bpf_map_delete_elem(&hook_ctx_map, &key);
			return 0;
		}
	}

	if (cfg && cfg->io_event_others_enabled) {
		LOG("others write exit: tgid=%d pid=%d ret=%d", tgid, pid, ret);
	}

	return 0;
}

#endif
