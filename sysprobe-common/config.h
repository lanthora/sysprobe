// SPDX-License-Identifier: Apache-2.0
#ifndef SYSPROBE_COMMON_CONFIG_H
#define SYSPROBE_COMMON_CONFIG_H

#ifndef CONFIG_RINGBUF_SIZE_MAX
#define CONFIG_RINGBUF_SIZE_MAX (262144)
#endif

#ifndef CONFIG_LOG_LEN_MAX
#define CONFIG_LOG_LEN_MAX (1024)
#endif

// 对于每进程(pproc)变量,最多可能管理的进程数
#ifndef CONFIG_PROCESS_NUMBER_MAX
#define CONFIG_PROCESS_NUMBER_MAX (10240)
#endif

// 最多可能并发的线程数,用来在进入和退出的 hook 点之间传递数据
#ifndef CONFIG_CONCURRENT_THREAD_MAX
#define CONFIG_CONCURRENT_THREAD_MAX (10240)
#endif

#ifndef CONFIG_CTL_SOCKET_PATH
#define CONFIG_CTL_SOCKET_PATH "/var/run/sysprobe-ctl.sock"
#endif

#ifndef CONFIG_DATA_SOCKET_PATH
#define CONFIG_DATA_SOCKET_PATH "/var/run/sysprobe-data.sock"
#endif

#ifndef CONFIG_CTL_BUFFER_SIZE_MAX
#define CONFIG_CTL_BUFFER_SIZE_MAX (1024)
#endif

#ifndef CONFIG_FILE_NAME_LEN_MAX
#define CONFIG_FILE_NAME_LEN_MAX (64)
#endif

#endif
