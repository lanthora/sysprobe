// SPDX-License-Identifier: Apache-2.0
#ifndef SYSPROBE_HANDLER_H
#define SYSPROBE_HANDLER_H

#include <cstddef>

int init_handler();
int handle_event(void *ctx, void *data, size_t len);

#endif
