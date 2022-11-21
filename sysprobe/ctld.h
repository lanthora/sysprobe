// SPDX-License-Identifier: Apache-2.0
#ifndef SYSPROBE_CTLD_H
#define SYSPROBE_CTLD_H

#include <sys/un.h>

class ctld {
    public:
	int start(struct sysprobe *skel);

    private:
	int handle_io_event_others(void *buffer, int len);
	int handle_log(void *buffer, int len);
	int handle_io_event_socket(void *buffer, int len);

    private:
	int init_socket_fd();
	int serve();
	int socket_fd_;
	struct sysprobe *skel_;
	struct sockaddr_un server_;
};

#endif
