// SPDX-License-Identifier: Apache-2.0
#ifndef SYSPROBE_COMMON_TYPES_H
#define SYSPROBE_COMMON_TYPES_H

#include "sysprobe-common/config.h"

// 内核通过 Ringbuf 上报的事件
enum {
	RB_EVENT_UNSPEC,
	RB_EVENT_LOG,
};

struct elog {
	unsigned int type; // always RB_EVENT_LOG
	unsigned long long nsec;
	char msg[CONFIG_LOG_LEN_MAX];
} __attribute__((__packed__));

// 与单个进程相关的配置,至少一个功能与默认行为不一致时才会初始化,初始化时字段默认为 0,
// io_event_socket_disabled, 默认表示不禁用 socket 的 io 事件上报
// io_event_others_enabled, 默认表示不启用其他类型 io 事件上报
struct pproc_cfg {
	int tgid;
	int io_event_socket_disabled;
	int io_event_others_enabled;
} __attribute__((__packed__));

// sysprobe-ctl 请求响应的事件
enum {
	CTL_EVENT_UNSPEC,
	CTL_EVENT_IO_EVENT,
};

struct ctl_io_event {
	unsigned int type; // always CTL_EVENT_IO_EVENT
	int tgid;
	int io_event_others_enabled;
	int ret;
} __attribute__((__packed__));

#endif
