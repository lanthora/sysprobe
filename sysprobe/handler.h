#ifndef SYSPROBE_HANDLER_H
#define SYSPROBE_HANDLER_H

#include <cstddef>

int register_sig_handler();
int handle_event(void *ctx, void *data, size_t len);
int handle_log_event(void *ctx, void *data, size_t len);

#endif
