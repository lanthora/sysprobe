// SPDX-License-Identifier: Apache-2.0
#include "sysprobe/ctld.h"
#include "errno.h"
#include "sysprobe-common/types.h"
#include "sysprobe/sysprobe.skel.h"
#include "sysprobe/util.h"
#include <bpf/bpf.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

int ctld::handle_io_event_others(void *buffer, int len)
{
	if (len != sizeof(struct ctl_io_event_others)) {
		ERR("Invalid argument");
		return 0;
	}

	struct ctl_io_event_others *event = (struct ctl_io_event_others *)buffer;
	struct pproc_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel_->maps.pproc_cfg_map), &event->tgid, &cfg);

	cfg.tgid = event->tgid;
	cfg.io_event_others_enabled = event->io_event_others_enabled;
	bpf_map_update_elem(bpf_map__fd(skel_->maps.pproc_cfg_map), &event->tgid, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int ctld::handle_log(void *buffer, int len)
{
	if (len != sizeof(struct ctl_log)) {
		ERR("Invalid argument");
		return 0;
	}

	struct ctl_log *event = (struct ctl_log *)buffer;
	int k0 = 0;
	struct global_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel_->maps.global_cfg_map), &k0, &cfg);

	cfg.log_enabled = event->log_enabled;
	bpf_map_update_elem(bpf_map__fd(skel_->maps.global_cfg_map), &k0, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int ctld::init_socket_fd()
{
	socket_fd_ = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (socket_fd_ == -1)
		return -errno;

	server_.sun_family = AF_UNIX;
	strcpy(server_.sun_path, CONFIG_CTL_SOCKET_PATH);

	if (unlink(CONFIG_CTL_SOCKET_PATH) && errno == EPERM)
		return -EPERM;

	if (bind(socket_fd_, (struct sockaddr *)&server_, sizeof(server_)) == -1)
		return -errno;

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
		if (size < CTL_TYPE_LEN) {
			ERR("size=[%d] strerror=[%s]", size, strerror(errno));
			break;
		}

		type = CTL_EVENT_UNSPEC;
		memcpy(&type, buffer, CTL_TYPE_LEN);
		switch (type) {
		case CTL_EVENT_IO_EVENT_OTHERS:
			handle_io_event_others(buffer, size);
			break;
		case CTL_EVENT_LOG:
			handle_log(buffer, size);
			break;
		}
		size = sendto(socket_fd_, buffer, size, 0, (struct sockaddr *)&peer, len);
		if (size == -1) {
			ERR("strerror=[%s] peer=[%s]", strerror(errno), peer.sun_path);
		}
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
