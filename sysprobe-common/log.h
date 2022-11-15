#ifndef SYSPROBE_COMMON_LOG_H
#define SYSPROBE_COMMON_LOG_H

#define LOG_LEN_MAX 1024

struct log_event {
	unsigned int len;
	char msg[LOG_LEN_MAX];
};

#endif