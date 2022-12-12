// SPDX-License-Identifier: Apache-2.0
#ifndef SYSPROBE_CALLBACK_H
#define SYSPROBE_CALLBACK_H

#include <cstddef>

int ring_buffer_callback(void *ctx, void *data, size_t len);

#endif
