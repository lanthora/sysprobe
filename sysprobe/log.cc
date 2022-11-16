#include "sysprobe-common/log.h"
#include "sysprobe/handler.h"
#include <ctime>
#include <iomanip>
#include <iostream>

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

int handle_log_event(void *ctx, void *data, size_t len)
{
	struct elog *e = (struct elog *)data;

	struct timespec now;
	clock_get_event_time(e->nsec, &now);

	struct tm t;
	char date_time[32];
	strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", localtime_r(&now.tv_sec, &t));
	std::cout << date_time << "." << std::setw(9) << std::setfill('0') << now.tv_nsec << " " << e->msg << std::endl;
	return 0;
}
