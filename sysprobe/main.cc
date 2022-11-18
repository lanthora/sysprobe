// SPDX-License-Identifier: Apache-2.0
#include "sysprobe/ctld.h"
#include "sysprobe/handler.h"
#include "sysprobe/sysprobe.skel.h"

int main()
{
	int retval = 0;
	struct sysprobe *skel = NULL;
	struct ring_buffer *rb = NULL;
	ctld ctl;

	retval = register_sig_handler();
	if (retval)
		goto out;

	skel = sysprobe__open_and_load();
	if (!skel)
		goto out;

	retval = sysprobe__attach(skel);
	if (retval)
		goto destory;

	retval = ctl.start(skel);
	if (retval)
		goto detach;

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
