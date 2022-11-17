// SPDX-License-Identifier: Apache-2.0
#include "errno.h"
#include "sysprobe-common/types.h"
#include "sysprobe/sysprobe.skel.h"
#include <bpf/bpf.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

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

static int create_ctld_socket_fd()
{
	int socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (socket_fd == -1)
		return -errno;

	struct sockaddr_un server;
	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, CONFIG_CTL_SOCKET_PATH);

	if (unlink(CONFIG_CTL_SOCKET_PATH) && errno == EPERM)
		return -EPERM;

	if (bind(socket_fd, (struct sockaddr *)&server, sizeof(server)) == -1)
		return -errno;

	return socket_fd;
}

static int sysprobectld(int socket_fd, struct sysprobe *skel)
{
	char buffer[CONFIG_CTL_BUFFER_SIZE_MAX + 1];
	socklen_t len;
	struct sockaddr_un peer;

	while (true) {
		len = sizeof(peer);
		int size = recvfrom(socket_fd, buffer, CONFIG_CTL_BUFFER_SIZE_MAX, 0, (struct sockaddr *)&peer, &len);
		if (size < sizeof(unsigned int))
			break;

		unsigned int type = CTL_EVENT_UNSPEC;
		memcpy(&type, buffer, sizeof(unsigned int));
		switch (type) {
		case CTL_EVENT_IO_EVENT:
			handle_ctl_io_event_others((struct ctl_io_event *)buffer, skel);
			break;
		}
		sendto(socket_fd, buffer, size, 0, (struct sockaddr *)&peer, len);
	}
	return 0;
}

int start_sysprobectld(struct sysprobe *skel)
{
	int socket_fd = create_ctld_socket_fd();
	if (socket_fd < 0)
		return socket_fd;

	std::thread sysprobectl_thread([&]() { sysprobectld(socket_fd, skel); });
	sysprobectl_thread.detach();
	return 0;
}
