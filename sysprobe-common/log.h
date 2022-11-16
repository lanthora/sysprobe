#ifndef SYSPROBE_COMMON_LOG_H
#define SYSPROBE_COMMON_LOG_H

#define LOG_LEN_MAX 1024

struct elog {
	unsigned int type;
	unsigned long long nsec;
	char msg[LOG_LEN_MAX];
};

#endif
