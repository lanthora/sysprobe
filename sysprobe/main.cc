// SPDX-License-Identifier: Apache-2.0
#include "sysprobe/callback.h"
#include "sysprobe/control.h"
#include "sysprobe/sysprobe.skel.h"
#include <csignal>
#include <cstdio>
#include <iostream>

static void handle_signal(int sig)
{
	std::cout << strsignal(sig) << std::endl;
}

int main()
{
	int retval = 0;
	struct sysprobe *skel = NULL;
	struct ring_buffer *rb = NULL;
	control ctrl;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	skel = sysprobe__open_and_load();
	if (!skel)
		goto out;

	retval = sysprobe__attach(skel);
	if (retval)
		goto destory;

	retval = ctrl.start(skel);
	if (retval)
		goto detach;

	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), ring_buffer_callback, NULL, NULL);
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
	std::cout << "Exit" << std::endl;
	return 0;
}
