// SPDX-License-Identifier: Apache-2.0
#ifndef SYSPROBE_COMMON_TYPES_H
#define SYSPROBE_COMMON_TYPES_H

#include "sysprobe-common/config.h"
#include <linux/limits.h>

// 内核通过 Ringbuf 上报的事件
enum {
	RB_EVENT_UNSPEC,
	RB_EVENT_LOG,
	RB_EVENT_STACK_TRACE,
};

struct event_log {
	unsigned int type /* = RB_EVENT_LOG */;
	unsigned long long nsec;
	char msg[CONFIG_LOG_LEN_MAX];
} __attribute__((__packed__));

struct event_stack_trace {
	unsigned int type /* = RB_EVENT_STACK_TRACE */;
	unsigned int stackid;
	int pid;
	char comm[16];
} __attribute__((__packed__));

// 与单个进程相关的配置,至少一个功能与默认行为不一致时才会初始化,初始化时字段默认为 0,
// io_event_socket_disabled, 默认表示不禁用 socket 的 io 事件上报
// io_event_others_enabled, 默认表示不启用其他类型 io 事件上报
struct pproc_cfg {
	int enabled;
	int io_event_socket_disabled;
	int io_event_regular_disabled;
	int io_event_others_enabled;
} __attribute__((__packed__));

// 全局配置,成员表示方式与 pproc_cfg 一致
struct global_cfg {
	int log_enabled;
	int kfree_skb_enabled;
	int nf_hook_slow_enabled;
	int sched_enabled;
	int tcp_probe_enabled;
} __attribute__((__packed__));

enum {
	CTL_EVENT_UNSPEC,
	CTL_EVENT_IO_EVENT_OTHERS_ENABLED,
	CTL_EVENT_LOG_ENABLED,
	CTL_EVENT_IO_EVENT_SOCKET_DISABLED,
	CTL_EVENT_PPROC_ENABLED,
	CTL_EVENT_KFREE_SKB_ENABLED,
	CTL_EVENT_NF_HOOK_SLOW_ENABLED,
	CTL_EVENT_SCHED_ENABLED,
	CTL_EVENT_TCP_PROBE_ENABLED,
	CTL_EVENT_CALL_STACK_TRACE,
};

struct ctl_io_event_others_enabled {
	unsigned int type /* = CTL_EVENT_IO_EVENT_OTHERS_ENABLED */;
	int tgid;
	int io_event_others_enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_log_enabled {
	unsigned int type /* = CTL_EVENT_LOG_ENABLED */;
	int log_enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_kfree_skb_enabled {
	unsigned int type /* = CTL_EVENT_KFREE_SKB_ENABLED */;
	int kfree_skb_enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_nf_hook_slow_enabled {
	unsigned int type /* = CTL_EVENT_NF_HOOK_SLOW_ENABLED */;
	int nf_hook_slow_enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_sched_enabled {
	unsigned int type /* = CTL_EVENT_SCHED_ENABLED */;
	int sched_enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_tcp_probe_enabled {
	unsigned int type /* = CTL_EVENT_TCP_PROBE_ENABLED */;
	int tcp_probe_enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_io_event_socket_disabled {
	unsigned int type /* = CTL_EVENT_IO_EVENT_OTHERS_ENABLED */;
	int tgid;
	int io_event_socket_disabled;
	int ret;
} __attribute__((__packed__));

struct ctl_pproc_enabled {
	unsigned int type /* = CTL_EVENT_PPROC_ENABLED */;
	int tgid;
	int enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_call_stack_trace {
	unsigned int type /* = CTL_EVENT_CALL_STACK_TRACE */;
	int retprobe;
	int pid;
	unsigned long long func_offset;
	char binary_path[PATH_MAX];
	int ret;
} __attribute__((__packed__));

#endif
