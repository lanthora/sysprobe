#include "sysprobe/handler.h"
#include "sysprobe/sysprobe.skel.h"
#include <cassert>

int main()
{
	int retval = 0;
	struct sysprobe *skel = NULL;
	struct ring_buffer *rb = NULL;

	skel = sysprobe__open_and_load();
	if (!skel)
		goto out;

	retval = sysprobe__attach(skel);
	if (retval)
		goto destory;

	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_event, NULL, NULL);
	if (!rb)
		goto detach;

	do {
		retval = ring_buffer__poll(rb, 100);
	} while (retval >= 0);

	ring_buffer__free(rb);
detach:
	sysprobe__detach(skel);
destory:
	sysprobe__destroy(skel);
out:
	return 0;
}
