#include "../sysprobe-common/log.h"
#include "sysprobe.skel.h"
#include <assert.h>
#include <iostream>

static int handle_log_event(void *ctx, void *data, size_t data_sz)
{
	struct log_event *e = (struct log_event *)data;
	std::cout << e->msg << std::endl;
	return 0;
}

int main()
{
	struct sysprobe *skel = sysprobe::open_and_load();
	assert(skel);

	int retval = sysprobe::attach(skel);
	assert(retval == 0);

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.log_ringbuf), handle_log_event, NULL, NULL);
	assert(rb);

	while (true) {
		retval = ring_buffer__poll(rb, 100);
		if (retval < 0)
			break;
	}
	return 0;
}