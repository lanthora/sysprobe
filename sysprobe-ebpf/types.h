// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_TYPES_H
#define SYSPROBE_EBPF_TYPES_H

#include "sysprobe-ebpf/vmlinux.h"

// 在使用 uprobe 时,可能存在被 hook 函数潜逃被 hook 函数的情况.在这种情况下仅通过进程号协程号或者进程号协程号无法正确匹配函数.
// 因此添加一个标记用来标识是哪个 hook 函数.
// 拆分多个 map 也可以解决这个问题,但会降低代码的可读性,维护多个 map 也会带来更多的心智负担.
enum {
	FUNC_SYSCALL_READ,
	FUNC_SYSCALL_WRITE,
	FUNC_SYSCALL_FUTEX,
};

// 用于标记 hook 点上下文的 key,目前已知进程号,线程号,go 的协程号.未来有需要新增字段是直接添加.
// 给需要的字段赋值并保持其他字段为 0, 在有效 id 不为0 的情况下,可以确保不冲突.
struct hook_ctx_key {
	unsigned int tgid;
	unsigned int pid;
	unsigned long long goid;
	unsigned int func;
} __attribute__((__packed__));

struct hook_ctx_value {
	unsigned int fd;
	char *buf;
	void *private_data;
	umode_t i_mode;
} __attribute__((__packed__));

#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

#define S_ISLNK(m) (((m)&S_IFMT) == S_IFLNK)
#define S_ISREG(m) (((m)&S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m)&S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m)&S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m)&S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m)&S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m)&S_IFMT) == S_IFSOCK)

#define FUTEX_WAIT 0
#define FUTEX_LOCK_PI 6
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_LOCK_PI2 13

#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_CLOCK_REALTIME 256
#define FUTEX_CMD_MASK ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

#endif
