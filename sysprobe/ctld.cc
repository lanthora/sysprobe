// SPDX-License-Identifier: Apache-2.0
#include "sysprobe/ctld.h"
#include "errno.h"
#include "sysprobe-common/types.h"
#include "sysprobe/sysprobe.skel.h"
#include <bpf/bpf.h>
#include <cassert>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

int ctld::handle_pproc_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_pproc_enabled));

	struct ctl_pproc_enabled *event = (struct ctl_pproc_enabled *)buffer;
	struct pproc_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel_->maps.pproc_cfg_map), &event->tgid, &cfg);

	cfg.enabled = event->enabled;
	bpf_map_update_elem(bpf_map__fd(skel_->maps.pproc_cfg_map), &event->tgid, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int ctld::handle_io_event_others_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_io_event_others_enabled));

	struct ctl_io_event_others_enabled *event = (struct ctl_io_event_others_enabled *)buffer;
	struct pproc_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel_->maps.pproc_cfg_map), &event->tgid, &cfg);

	cfg.io_event_others_enabled = event->io_event_others_enabled;
	bpf_map_update_elem(bpf_map__fd(skel_->maps.pproc_cfg_map), &event->tgid, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int ctld::handle_io_event_socket_disabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_io_event_socket_disabled));

	struct ctl_io_event_socket_disabled *event = (struct ctl_io_event_socket_disabled *)buffer;
	struct pproc_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel_->maps.pproc_cfg_map), &event->tgid, &cfg);

	cfg.io_event_socket_disabled = event->io_event_socket_disabled;
	bpf_map_update_elem(bpf_map__fd(skel_->maps.pproc_cfg_map), &event->tgid, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int ctld::handle_log_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_log_enabled));

	struct ctl_log_enabled *event = (struct ctl_log_enabled *)buffer;

	int zero = 0;
	struct global_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel_->maps.global_cfg_map), &zero, &cfg);

	cfg.log_enabled = event->log_enabled;
	bpf_map_update_elem(bpf_map__fd(skel_->maps.global_cfg_map), &zero, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int ctld::handle_kfree_skb_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_kfree_skb_enabled));

	struct ctl_kfree_skb_enabled *event = (struct ctl_kfree_skb_enabled *)buffer;

	int zero = 0;
	struct global_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel_->maps.global_cfg_map), &zero, &cfg);

	cfg.kfree_skb_enabled = event->kfree_skb_enabled;
	bpf_map_update_elem(bpf_map__fd(skel_->maps.global_cfg_map), &zero, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int ctld::handle_nf_hook_slow_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_nf_hook_slow_enabled));

	struct ctl_nf_hook_slow_enabled *event = (struct ctl_nf_hook_slow_enabled *)buffer;

	int zero = 0;
	struct global_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel_->maps.global_cfg_map), &zero, &cfg);

	cfg.nf_hook_slow_enabled = event->nf_hook_slow_enabled;
	bpf_map_update_elem(bpf_map__fd(skel_->maps.global_cfg_map), &zero, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int ctld::init_socket_fd()
{
	socket_fd_ = socket(AF_UNIX, SOCK_DGRAM, 0);
	assert(socket_fd_ != 0);

	server_.sun_family = AF_UNIX;
	strcpy(server_.sun_path, CONFIG_CTL_SOCKET_PATH);

	assert(!unlink(CONFIG_CTL_SOCKET_PATH) || errno != EPERM);
	assert(bind(socket_fd_, (struct sockaddr *)&server_, sizeof(server_)) != -1);

	return 0;
}

int ctld::serve()
{
	static const int CTL_TYPE_LEN = 4;
	char buffer[CONFIG_CTL_BUFFER_SIZE_MAX + 1];
	socklen_t len;
	struct sockaddr_un peer;
	int size;
	unsigned int type;

	while (true) {
		len = sizeof(peer);
		size = recvfrom(socket_fd_, buffer, CONFIG_CTL_BUFFER_SIZE_MAX, 0, (struct sockaddr *)&peer, &len);
		assert(size >= CTL_TYPE_LEN);

		type = CTL_EVENT_UNSPEC;
		memcpy(&type, buffer, CTL_TYPE_LEN);
		switch (type) {
		case CTL_EVENT_LOG_ENABLED:
			handle_log_enabled(buffer, size);
			break;
		case CTL_EVENT_PPROC_ENABLED:
			handle_pproc_enabled(buffer, size);
			break;
		case CTL_EVENT_IO_EVENT_OTHERS_ENABLED:
			handle_io_event_others_enabled(buffer, size);
			break;
		case CTL_EVENT_IO_EVENT_SOCKET_DISABLED:
			handle_io_event_socket_disabled(buffer, size);
			break;
		case CTL_EVENT_KFREE_SKB_ENABLED:
			handle_kfree_skb_enabled(buffer, size);
			break;
		case CTL_EVENT_NF_HOOK_SLOW_ENABLED:
			handle_nf_hook_slow_enabled(buffer, size);
			break;
		}
		sendto(socket_fd_, buffer, size, 0, (struct sockaddr *)&peer, len);
	}
	close(socket_fd_);
	return size;
}

int ctld::start(struct sysprobe *skel)
{
	int ret;

	if (!skel)
		return -EINVAL;
	skel_ = skel;

	ret = init_socket_fd();
	if (ret)
		return ret;

	std::thread serve_thread([&]() { serve(); });
	serve_thread.detach();
	return 0;
}
