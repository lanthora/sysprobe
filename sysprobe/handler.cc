// SPDX-License-Identifier: Apache-2.0
#include "sysprobe/handler.h"
#include "sysprobe-common/types.h"
#include "sysprobe/handler.h"
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>

static int fd;
static struct sockaddr_un addr;

static void handle_signal(int sig)
{
	std::cout << strsignal(sig) << std::endl;
}

int init_handler()
{
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (fd == -1)
		return -errno;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, CONFIG_DATA_SOCKET_PATH);
	return 0;
}

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
	struct elog *e = (struct elog *)data;

	struct timespec now;
	clock_get_event_time(e->nsec, &now);

	struct tm t;
	char date_time[32];
	strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", localtime_r(&now.tv_sec, &t));
	printf("[%s.%09lu] %s\n", date_time, now.tv_nsec, e->msg);
	return 0;
}

int handle_event(void *ctx, void *data, size_t len)
{
	unsigned int type = RB_EVENT_UNSPEC;

	if (len >= sizeof(unsigned int))
		type = *(unsigned int *)data;

	switch (type) {
	case RB_EVENT_UNSPEC:
		break;
	case RB_EVENT_LOG:
		handle_log_event(ctx, data, len);
		break;
	default:
		sendto(fd, data, len, 0, (struct sockaddr *)&addr, sizeof(addr));
		break;
	}
	return 0;
}
