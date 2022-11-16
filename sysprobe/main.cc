#include "sysprobe/handler.h"
#include "sysprobe/sysprobe.skel.h"
#include <cassert>

int main()
{
	struct sysprobe *skel = sysprobe::open_and_load();
	assert(skel);

	int retval = sysprobe::attach(skel);
	assert(retval == 0);

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_event, NULL, NULL);
	assert(rb);

	while (true) {
		retval = ring_buffer__poll(rb, 100);
		if (retval < 0)
			break;
	}
	return 0;
}
