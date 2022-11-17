#include "sysprobe/handler.h"
#include "sysprobe-common/types.h"
#include <csignal>
#include <cstring>
#include <iostream>

static void handle_signal(int sig)
{
	std::cout << strsignal(sig) << std::endl;
}

int register_sig_handler()
{
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
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
		break;
	}
	return 0;
}
