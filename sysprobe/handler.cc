#include "sysprobe/handler.h"
#include "sysprobe-common/event.h"
#include <cassert>
#include <iostream>

int handle_event(void *ctx, void *data, size_t len)
{
	unsigned int type = RB_EVENT_RESERVE;

	if (len >= sizeof(unsigned int))
		type = *(unsigned int *)data;

	switch (type) {
	case RB_EVENT_RESERVE:
		break;
	case RB_EVENT_LOG:
		handle_log_event(ctx, data, len);
		break;
	default:
		break;
	}
	return 0;
}
