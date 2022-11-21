// SPDX-License-Identifier: GPL-2.0-only
#ifndef SYSPROBE_EBPF_TYPES_H
#define SYSPROBE_EBPF_TYPES_H

// 在使用 uprobe 时,可能存在被 hook 函数潜逃被 hook 函数的情况.在这种情况下仅通过进程号协程号或者进程号协程号无法正确匹配函数.
// 因此添加一个标记用来标识是哪个 hook 函数.
// 拆分多个 map 也可以解决这个问题,但会降低代码的可读性,维护多个 map 也会带来更多的心智负担.
enum {
	FUNC_SYSCALL_READ,
	FUNC_SYSCALL_WRITE,
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
	char *buf;

} __attribute__((__packed__));

#endif
