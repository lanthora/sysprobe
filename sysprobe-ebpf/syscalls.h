// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_SYSCALLS_H
#define SYSPROBE_EBPF_SYSCALLS_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/maps.h"
#include "sysprobe-ebpf/types.h"
#include "sysprobe-ebpf/vmlinux.h"

static struct file *fd_to_file(unsigned int idx)
{
	struct file *file = NULL;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);

	unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
	if (idx > max_fds)
		return NULL;

	struct file **fd = BPF_CORE_READ(fdt, fd);
	bpf_probe_read_kernel(&file, sizeof(file), fd + idx);
	return file;
}

static umode_t file_to_i_mode(struct file *file)
{
	return BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT;
}

static void *file_to_private_data(struct file *file)
{
	return BPF_CORE_READ(file, private_data);
}

static struct qstr file_to_d_name(struct file *file)
{
	return BPF_CORE_READ(file, f_path.dentry, d_name);
}

static int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	unsigned int fd = (unsigned int)ctx->args[0];
	char *buf = (char *)ctx->args[1];
	size_t count = (size_t)ctx->args[2];

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	struct file *file = fd_to_file(fd);
	if (!file)
		return 0;

	void *private_data = file_to_private_data(file);
	umode_t i_mode = file_to_i_mode(file);
	struct qstr d_name = file_to_d_name(file);

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_READ, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = fd, .buf = buf, .private_data = private_data, .i_mode = i_mode };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);

	switch (i_mode) {
	case S_IFSOCK:
		if (!cfg->io_event_socket_disabled) {
			LOG("socket read enter: tgid=%d pid=%d fd=%d count=%d", tgid, pid, fd, count);
		}
		break;
	case S_IFREG:
		if (!cfg->io_event_regular_disabled) {
			char name[CONFIG_FILE_NAME_LEN_MAX] = { 0 };
			bpf_probe_read_kernel(name, sizeof(name) - 1, d_name.name);
			LOG("reg read enter: tgid=%d pid=%d fd=%d count=%d name=%s", tgid, pid, fd, count, name);
		}
		break;
	default:
		if (cfg->io_event_others_enabled) {
			LOG("others read enter: tgid=%d pid=%d fd=%d i_mode=%d", tgid, pid, fd, i_mode);
		}
		break;
	}

	return 0;
}

static int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	int ret = (int)ctx->ret;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_READ, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = (struct hook_ctx_value *)bpf_map_lookup_elem(&hook_ctx_map, &key);

	if (!value)
		return 0;

	switch (value->i_mode) {
	case S_IFSOCK:
		if (!cfg->io_event_socket_disabled) {
			LOG("socket read exit: tgid=%d pid=%d fd=%d ret=%d", tgid, pid, value->fd, ret);
		}
		break;
	case S_IFREG:
		if (!cfg->io_event_regular_disabled) {
			LOG("reg read exit: tgid=%d pid=%d fd=%d ret=%d", tgid, pid, value->fd, ret);
		}
		break;
	default:
		if (cfg->io_event_others_enabled) {
			LOG("others read exit: tgid=%d pid=%d fd=%d ret=%d", tgid, pid, value->fd, ret);
		}
		break;
	}

	bpf_map_delete_elem(&hook_ctx_map, &key);

	return 0;
}

static int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	unsigned int fd = (unsigned int)ctx->args[0];
	char *buf = (char *)ctx->args[1];
	size_t count = (size_t)ctx->args[2];

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	struct file *file = fd_to_file(fd);
	if (!file)
		return 0;

	void *private_data = file_to_private_data(file);
	umode_t i_mode = file_to_i_mode(file);
	struct qstr d_name = file_to_d_name(file);

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_WRITE, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = fd, .buf = buf, .private_data = private_data, .i_mode = i_mode };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);

	switch (i_mode) {
	case S_IFSOCK:
		if (!cfg->io_event_socket_disabled) {
			LOG("socket write enter: tgid=%d pid=%d fd=%d count=%d", tgid, pid, fd, count);
		}
		break;
	case S_IFREG:
		if (!cfg->io_event_regular_disabled) {
			char name[CONFIG_FILE_NAME_LEN_MAX] = { 0 };
			bpf_probe_read_kernel(name, sizeof(name) - 1, d_name.name);
			LOG("reg write enter: tgid=%d pid=%d fd=%d count=%d name=%s", tgid, pid, fd, count, name);
		}
		break;
	default:
		if (cfg->io_event_others_enabled) {
			LOG("others write enter: tgid=%d pid=%d fd=%d count=%d", tgid, pid, fd, count);
		}
		break;
	}

	return 0;
}

static int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	int ret = (int)ctx->ret;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_WRITE, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = (struct hook_ctx_value *)bpf_map_lookup_elem(&hook_ctx_map, &key);

	if (!value)
		return 0;

	switch (value->i_mode) {
	case S_IFSOCK:
		if (!cfg->io_event_socket_disabled) {
			LOG("socket write exit: tgid=%d pid=%d fd=%d ret=%d", tgid, pid, value->fd, ret);
		}
		break;
	case S_IFREG:
		if (!cfg->io_event_regular_disabled) {
			LOG("reg write exit: tgid=%d pid=%d fd=%d ret=%d", tgid, pid, value->fd, ret);
		}
		break;
	default:
		if (cfg->io_event_others_enabled) {
			LOG("others write exit: tgid=%d pid=%d fd=%d ret=%d", tgid, pid, value->fd, ret);
		}
		break;
	}

	bpf_map_delete_elem(&hook_ctx_map, &key);
	return 0;
}

static int trace_sys_enter_futex(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	int futex_op = ctx->args[1] & FUTEX_CMD_MASK;

	if (futex_op != FUTEX_WAIT && futex_op != FUTEX_WAIT_BITSET && futex_op != FUTEX_WAIT_REQUEUE_PI &&
	    futex_op != FUTEX_LOCK_PI && futex_op != FUTEX_LOCK_PI2)
		return 0;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_FUTEX, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = {};
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);

	LOG("futex enter: tgid=%d pid=%d", tgid, pid);
	return 0;
}

static int trace_sys_exit_futex(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_FUTEX, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = (struct hook_ctx_value *)bpf_map_lookup_elem(&hook_ctx_map, &key);

	if (!value)
		return 0;

	LOG("futex exit: tgid=%d pid=%d", tgid, pid);

	bpf_map_delete_elem(&hook_ctx_map, &key);
	return 0;
}

static int trace_sys_enter_futex_waitv(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("futex_waitv enter: tgid=%d pid=%d", tgid, pid);
	return 0;
}

static int trace_sys_exit_futex_waitv(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("futex_waitv exit: tgid=%d pid=%d", tgid, pid);
	return 0;
}

#endif
