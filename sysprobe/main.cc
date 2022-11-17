// SPDX-License-Identifier: Apache-2.0
#include "sysprobe/handler.h"
#include "sysprobe/sysprobe.skel.h"

extern int start_sysprobectld(struct sysprobe *skel);

int main()
{
	int retval = 0;
	struct sysprobe *skel = NULL;
	struct ring_buffer *rb = NULL;

	retval = register_sig_handler();
	if (retval)
		goto out;

	skel = sysprobe__open_and_load();
	if (!skel)
		goto out;

	retval = sysprobe__attach(skel);
	if (retval)
		goto destory;

	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_event, NULL, NULL);
	if (!rb)
		goto detach;

	retval = start_sysprobectld(skel);
	if (retval)
		goto rbfree;

	do {
		retval = ring_buffer__poll(rb, 100);
	} while (retval >= 0);

rbfree:
	ring_buffer__free(rb);
detach:
	sysprobe__detach(skel);
destory:
	sysprobe__destroy(skel);
out:
	return 0;
}
