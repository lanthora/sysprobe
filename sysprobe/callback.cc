// SPDX-License-Identifier: Apache-2.0
#include "sysprobe/callback.h"
#include "sysprobe-common/types.h"
#include "sysprobe-library/addr2line.h"
#include "sysprobe-library/process.h"
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
extern class process_collector p_collector;

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

static void stack_trace_callback(bfd_vma pc, const char *functionname, const char *filename, int line, void *data)
{
	int idx = *(int *)data;
	printf("#%d %p at %s in %s:%d\n", idx, (void *)pc, functionname, filename, line);
}

static int handle_stack_trace_event(void *ctx, void *data, size_t len)
{
	struct event_stack_trace *e = (struct event_stack_trace *)data;
	uintptr_t ip[MAX_STACK_DEPTH];
	uint32_t stackid = e->stackid;
	struct addr2line *addr2line_ctx;

	printf("stack trace: pid=%d comm=%s\n", e->pid, e->comm);

	memset(ip, 0, sizeof(ip));
	int ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stack_trace_map), &stackid, &ip);
	if (ret) {
		printf("stack_trace_map lookup failed\n");
		return 0;
	}

	addr2line_ctx = p_collector.fetch_addr2line_ctx(e->pid);
	if (!addr2line_ctx) {
		printf("fetch_addr2line_ctx failed\n");
		return 0;
	}

	for (int idx = 0; idx < MAX_STACK_DEPTH; ++idx) {
		if (!ip[idx])
			break;
		addr2line_search(addr2line_ctx, ip[idx], stack_trace_callback, &idx);
	}
	printf("\n");

	return 0;
}

static int handle_sched_event(void *ctx, void *data, size_t len)
{
	struct event_sched *e = (struct event_sched *)data;
	switch (e->op) {
	case 0: // fork
		p_collector.copy_process_item(e->pid, e->ppid);
		break;
	case 1: // execve
		p_collector.update_process_item(e->pid);
		break;
	case 2: // exit
		p_collector.delete_process_item(e->pid);
		break;
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
	case RB_EVENT_SCHED:
		handle_sched_event(ctx, data, len);
		break;
	default:
		sendto(fd, data, len, 0, (struct sockaddr *)&addr, sizeof(addr));
		break;
	}
	return 0;
}
