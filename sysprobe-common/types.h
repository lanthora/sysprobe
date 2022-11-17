#ifndef SYSPROBE_COMMON_TYPES_H
#define SYSPROBE_COMMON_TYPES_H

#include "sysprobe-common/config.h"

enum {
	RB_EVENT_UNSPEC,
	RB_EVENT_LOG,
};

struct elog {
	unsigned int type;
	unsigned long long nsec;
	char msg[CONFIG_LOG_LEN_MAX];
} __attribute__((__packed__));

struct pproc_cfg {
	int tgid;
	int io_event_enabled;
} __attribute__((__packed__));

#endif
