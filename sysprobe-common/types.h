// SPDX-License-Identifier: Apache-2.0
#ifndef SYSPROBE_COMMON_TYPES_H
#define SYSPROBE_COMMON_TYPES_H

#include "sysprobe-common/config.h"

// 内核通过 Ringbuf 上报的事件
enum {
	RB_EVENT_UNSPEC,
	RB_EVENT_LOG,
	RB_EVENT_PROC,
};

struct elog {
	// RB_EVENT_LOG
	unsigned int type;
	unsigned long long nsec;
	char msg[CONFIG_LOG_LEN_MAX];
} __attribute__((__packed__));

struct eproc {
	// RB_EVENT_PROC
	unsigned int type;
	unsigned long long nsec;
	// 0: 保留
	// 1: 进程创建
	// 2: 进程退出
	int tracepoint;
	union {
		// 进程退出时的进程号
		int pid;
		// 进程创建时的父进程号
		int parent_pid;
	};
	// 进程创建时的子进程号
	int child_pid;

} __attribute__((__packed__));

// 与单个进程相关的配置,至少一个功能与默认行为不一致时才会初始化,初始化时字段默认为 0,
// io_event_socket_disabled, 默认表示不禁用 socket 的 io 事件上报
// io_event_others_enabled, 默认表示不启用其他类型 io 事件上报
struct pproc_cfg {
	int tgid;
	int io_event_socket_disabled;
	int io_event_others_enabled;
} __attribute__((__packed__));

// 全局配置,成员表示方式与 pproc_cfg 一致
struct global_cfg {
	int log_enabled;
} __attribute__((__packed__));

// sysprobe-ctl 请求响应的事件
enum {
	CTL_EVENT_UNSPEC,
	CTL_EVENT_IO_EVENT_OTHERS,
	CTL_EVENT_LOG,
};

struct ctl_io_event_others {
	unsigned int type; // always CTL_EVENT_IO_EVENT_OTHERS
	int tgid;
	int io_event_others_enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_log {
	unsigned int type; // always CTL_EVENT_LOG
	int log_enabled;
	int ret;
} __attribute__((__packed__));

#endif
