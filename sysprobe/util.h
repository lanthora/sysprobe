// SPDX-License-Identifier: Apache-2.0
#ifndef SYSPROBE_UTIL_H
#define SYSPROBE_UTIL_H

#include <stdio.h>
#include <time.h>

#define INFO(fmt, arg...)                                                                                              \
	do {                                                                                                           \
		time_t now__ = time(NULL);                                                                             \
		struct tm *t__ = localtime(&now__);                                                                    \
		fprintf(stdout, "[%04d-%02d-%02d %02d:%02d:%02d] [%s:%d] " fmt "\n", t__->tm_year + 1900,              \
			t__->tm_mon + 1, t__->tm_mday, t__->tm_hour, t__->tm_min, t__->tm_sec, __FILE__, __LINE__,     \
			##arg);                                                                                        \
		fflush(stdout);                                                                                        \
	} while (0)

#define ERR(fmt, arg...)                                                                                               \
	do {                                                                                                           \
		time_t now__ = time(NULL);                                                                             \
		struct tm *t__ = localtime(&now__);                                                                    \
		fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d] [%s:%d] " fmt "\n", t__->tm_year + 1900,              \
			t__->tm_mon + 1, t__->tm_mday, t__->tm_hour, t__->tm_min, t__->tm_sec, __FILE__, __LINE__,     \
			##arg);                                                                                        \
		fflush(stderr);                                                                                        \
	} while (0)

#endif
