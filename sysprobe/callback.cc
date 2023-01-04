// SPDX-License-Identifier: Apache-2.0
#include "sysprobe/callback.h"
#include "sysprobe-common/types.h"
#include "sysprobe/sysprobe.skel.h"
#include <bpf/bpf.h>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>

extern struct sysprobe *skel;

// 根据系统启动时间和内核记录的纳秒时间戳计算事件产生的时间
static int clock_get_event_time(unsigned long long nsec, struct timespec *now)
{
	static const long NS_PER_SEC = 1000000000L;
	struct timespec boot, tmp;

	clock_gettime(CLOCK_REALTIME, &boot);
	clock_gettime(CLOCK_BOOTTIME, &tmp);
	if (boot.tv_nsec < tmp.tv_nsec) {
		boot.tv_nsec += NS_PER_SEC;
		boot.tv_sec -= 1L;
	}
	boot.tv_nsec -= tmp.tv_nsec;
	boot.tv_sec -= tmp.tv_sec;

	nsec += boot.tv_nsec;
	now->tv_nsec = nsec % NS_PER_SEC;
	now->tv_sec = boot.tv_sec + (nsec / NS_PER_SEC);
	return 0;
}

static int handle_log_event(void *ctx, void *data, size_t len)
{
	struct event_log *e = (struct event_log *)data;

	struct timespec now;
	clock_get_event_time(e->nsec, &now);

	struct tm t;
	char date_time[32];
	strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", localtime_r(&now.tv_sec, &t));
	printf("[%s.%09lu] %s\n", date_time, now.tv_nsec, e->msg);
	return 0;
}

static int handle_stack_trace_event(void *ctx, void *data, size_t len)
{
	struct event_stack_trace *e = (struct event_stack_trace *)data;
	void *ip[MAX_STACK_DEPTH];
	uint32_t stackid = e->stackid;

	printf("stack trace: pid=%d comm=%s\n", e->pid, e->comm);

	memset(ip, 0, sizeof(ip));
	int ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stack_trace_map), &stackid, &ip);
	if (ret) {
		printf("stack_trace_map lookup failed\n");
		return 0;
	}

	// TODO: 显示行号和函数名
	for (int idx = 0; idx < MAX_STACK_DEPTH; ++idx) {
		if (!ip[idx])
			break;
		printf("%p\n", ip[idx]);
	}
	return 0;
}

int ring_buffer_callback(void *ctx, void *data, size_t len)
{
	unsigned int type = RB_EVENT_UNSPEC;
	static const int fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	static const struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
		.sun_path = CONFIG_DATA_SOCKET_PATH,
	};

	if (len >= sizeof(unsigned int))
		type = *(unsigned int *)data;

	switch (type) {
	case RB_EVENT_UNSPEC:
		break;
	case RB_EVENT_LOG:
		handle_log_event(ctx, data, len);
		break;
	case RB_EVENT_STACK_TRACE:
		handle_stack_trace_event(ctx, data, len);
		break;
	default:
		sendto(fd, data, len, 0, (struct sockaddr *)&addr, sizeof(addr));
		break;
	}
	return 0;
}
