// SPDX-License-Identifier: Apache-2.0
#include "errno.h"
#include "sysprobe-common/types.h"
#include "sysprobe/sysprobe.skel.h"
#include <bpf/bpf.h>

static int handle_ctl_io_event_others(struct ctl_io_event *event, struct sysprobe *skel)
{
	struct pproc_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg);

	cfg.tgid = event->tgid;
	cfg.io_event_others_enabled = event->io_event_others_enabled;
	bpf_map_update_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int sysprobectl(struct sysprobe *skel)
{
	// 测试代码
	struct ctl_io_event event = {
		.type = CTL_EVENT_IO_EVENT,
		.tgid = 18329,
		.io_event_others_enabled = true,
	};
	handle_ctl_io_event_others(&event, skel);
	return 0;
}
