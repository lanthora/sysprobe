#include "sysprobe-common/log.h"
#include "sysprobe/handler.h"
#include <ctime>
#include <iostream>

int handle_log_event(void *ctx, void *data, size_t len)
{
	time_t t = time(0);
	char now[32] = { 0 };
	strftime(now, sizeof(now), "%Y-%m-%d %H:%M:%S", localtime(&t));

	struct elog *e = (struct elog *)data;

	std::cout << now << " " << e->msg << std::endl;
	return 0;
}
