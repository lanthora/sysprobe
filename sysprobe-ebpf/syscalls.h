// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_SYSCALLS_H
#define SYSPROBE_EBPF_SYSCALLS_H

#include "sysprobe-ebpf/log.h"
#include "sysprobe-ebpf/maps.h"
#include "sysprobe-ebpf/types.h"
#include "sysprobe-ebpf/vmlinux.h"
#include <asm/unistd.h>

#define ntohs(__x) (((__x & 0xff00) >> 8) | ((__x & 0x00ff) << 8))

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

static struct socket *file_to_private_data(struct file *file)
{
	return (struct socket *)BPF_CORE_READ(file, private_data);
}

static inline struct qstr file_to_d_name(struct file *file)
{
	return BPF_CORE_READ(file, f_path.dentry, d_name);
}

static umode_t fd_to_i_mode(unsigned int idx)
{
	struct file *file = fd_to_file(idx);
	return file_to_i_mode(file);
}

static struct socket *fd_to_socket(unsigned int idx)
{
	struct file *file = fd_to_file(idx);
	return file_to_private_data(file);
}

static inline struct qstr fd_to_d_name(unsigned int idx)
{
	struct file *file = fd_to_file(idx);
	return file_to_d_name(file);
}

static void trace_io_event_common(struct pproc_cfg *cfg, struct hook_ctx_key *key, struct hook_ctx_value *value, int ret)
{
	if (!cfg || !key || !value)
		return;

	unsigned int func = key->func;
	unsigned int tgid = key->tgid;
	unsigned int pid = key->pid;
	unsigned int fd = value->fd;
	size_t count = value->count;
	unsigned long long latency = bpf_ktime_get_boot_ns() - value->nsec;

	umode_t i_mode = fd_to_i_mode(fd);

	if (i_mode == S_IFSOCK && !cfg->io_event_socket_disabled) {
		struct socket *socket = fd_to_socket(fd);
		struct sock *sk = BPF_CORE_READ(socket, sk);
		u32 local_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		u32 remote_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		u16 local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
		u16 remote_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
		remote_port = ntohs(remote_port);
		LOG("socket file: func=%d tgid=%d pid=%d fd=%d ret=%d local=%pI4:%u remote=%pI4:%u latency=%u", func, tgid, pid, fd, ret, &local_addr,
		    local_port, &remote_addr, remote_port, latency);
		return;
	}

	if (i_mode == S_IFREG && !cfg->io_event_regular_disabled) {
		struct qstr d_name = fd_to_d_name(fd);
		char name[CONFIG_FILE_NAME_LEN_MAX] = { 0 };
		bpf_probe_read_kernel(name, sizeof(name) - 1, d_name.name);
		LOG("regular file: func=%d tgid=%d pid=%d fd=%d name=%s ret=%d latency=%u", func, tgid, pid, fd, name, ret, latency);
		return;
	}

	if (cfg->io_event_others_enabled) {
		LOG("others file: func=%d tgid=%d pid=%d fd=%d i_mode=%d ret=%d latency=%u", func, tgid, pid, fd, i_mode, ret, latency);
		return;
	}
}

static int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	unsigned int fd = (unsigned int)ctx->args[0];
	char *buf = (char *)ctx->args[1];
	size_t count = (size_t)ctx->args[2];

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_READ, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = fd, .buf = buf, .count = count, .nsec = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);

	return 0;
}

static int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	int ret = (int)ctx->ret;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_READ, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	trace_io_event_common(cfg, &key, value, ret);

	bpf_map_delete_elem(&hook_ctx_map, &key);

	return 0;
}

static int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	unsigned int fd = (unsigned int)ctx->args[0];
	char *buf = (char *)ctx->args[1];
	size_t count = (size_t)ctx->args[2];

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_WRITE, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = fd, .buf = buf, .count = count, .nsec = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);

	return 0;
}

static int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	int ret = (int)ctx->ret;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_WRITE, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	trace_io_event_common(cfg, &key, value, ret);

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

	if (futex_op != FUTEX_WAIT && futex_op != FUTEX_WAIT_BITSET && futex_op != FUTEX_WAIT_REQUEUE_PI && futex_op != FUTEX_LOCK_PI &&
	    futex_op != FUTEX_LOCK_PI2)
		return 0;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_FUTEX, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .nsec = bpf_ktime_get_boot_ns() };
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
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

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

static int trace_sys_enter_readv(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("trace_sys_enter_readv");
	return 0;
}

static int trace_sys_exit_readv(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("trace_sys_exit_readv");
	return 0;
}

static int trace_sys_enter_writev(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	unsigned int fd = (unsigned int)ctx->args[0];
	struct iovec *iov = (struct iovec *)ctx->args[1];
	int iovcnt = (int)ctx->args[2];

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_WRITEV, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = fd, .iov = iov, .iovcnt = iovcnt, .nsec = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);
	return 0;
}

static int trace_sys_exit_writev(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	int ret = (int)ctx->ret;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_WRITEV, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	trace_io_event_common(cfg, &key, value, ret);

	bpf_map_delete_elem(&hook_ctx_map, &key);

	return 0;
}

static int trace_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	unsigned int fd = (unsigned int)ctx->args[0];
	char *buf = (char *)ctx->args[1];
	size_t count = (size_t)ctx->args[2];

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_RECVFROM, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = fd, .buf = buf, .count = count, .nsec = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);

	return 0;
}

static int trace_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	int ret = (int)ctx->ret;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_RECVFROM, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	trace_io_event_common(cfg, &key, value, ret);

	bpf_map_delete_elem(&hook_ctx_map, &key);

	return 0;
}

static int trace_sys_enter_recvmsg(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("trace_sys_enter_recvmsg");
	return 0;
}

static int trace_sys_exit_recvmsg(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("trace_sys_exit_recvmsg");
	return 0;
}

static int trace_sys_enter_recvmmsg(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("trace_sys_enter_recvmmsg");
	return 0;
}

static int trace_sys_exit_recvmmsg(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("trace_sys_exit_recvmmsg");
	return 0;
}

static int trace_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("trace_sys_enter_sendto");
	return 0;
}

static int trace_sys_exit_sendto(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("trace_sys_exit_sendto");
	return 0;
}

static int trace_sys_enter_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("trace_sys_enter_sendmsg");
	return 0;
}

static int trace_sys_exit_sendmsg(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("trace_sys_exit_sendmsg");
	return 0;
}

static int trace_sys_enter_sendmmsg(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("trace_sys_enter_sendmmsg");
	return 0;
}

static int trace_sys_exit_sendmmsg(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("trace_sys_exit_sendmmsg");
	return 0;
}

static int trace_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	switch (ctx->id) {
	case __NR_read:
		trace_sys_enter_read(ctx);
		break;
	case __NR_write:
		trace_sys_enter_write(ctx);
		break;
	case __NR_futex:
		trace_sys_enter_futex(ctx);
		break;
	case __NR_futex_waitv:
		trace_sys_enter_futex_waitv(ctx);
		break;
	case __NR_readv:
		trace_sys_enter_readv(ctx);
		break;
	case __NR_writev:
		trace_sys_enter_writev(ctx);
		break;
	case __NR_recvfrom:
		trace_sys_enter_recvfrom(ctx);
		break;
	case __NR_recvmsg:
		trace_sys_enter_recvmsg(ctx);
		break;
	case __NR_recvmmsg:
		trace_sys_enter_recvmmsg(ctx);
		break;
	case __NR_sendto:
		trace_sys_enter_sendto(ctx);
		break;
	case __NR_sendmsg:
		trace_sys_enter_sendmsg(ctx);
		break;
	case __NR_sendmmsg:
		trace_sys_enter_sendmmsg(ctx);
		break;
	}
	return 0;
}

static int trace_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	switch (ctx->id) {
	case __NR_read:
		trace_sys_exit_read(ctx);
		break;
	case __NR_write:
		trace_sys_exit_write(ctx);
		break;
	case __NR_futex:
		trace_sys_exit_futex(ctx);
		break;
	case __NR_futex_waitv:
		trace_sys_exit_futex_waitv(ctx);
		break;
	case __NR_recvfrom:
		trace_sys_exit_recvfrom(ctx);
		break;
	case __NR_readv:
		trace_sys_exit_readv(ctx);
		break;
	case __NR_writev:
		trace_sys_exit_writev(ctx);
		break;
	case __NR_recvmsg:
		trace_sys_exit_recvmsg(ctx);
		break;
	case __NR_recvmmsg:
		trace_sys_exit_recvmmsg(ctx);
		break;
	case __NR_sendto:
		trace_sys_exit_sendto(ctx);
		break;
	case __NR_sendmsg:
		trace_sys_exit_sendmsg(ctx);
		break;
	case __NR_sendmmsg:
		trace_sys_exit_sendmmsg(ctx);
		break;
	}
	return 0;
}

#endif
