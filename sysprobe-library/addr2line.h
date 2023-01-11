// SPDX-License-Identifier: Apache-2.0
#ifndef SYSPROBE_ADDR2LINE_H
#define SYSPROBE_ADDR2LINE_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PACKAGE "libaddr2line"
#define PACKAGE_VERSION "0.0.0"
#include <bfd.h>

struct addr2line {
	bfd *abfd;
	bfd_vma addr_start;
	asection *section;
	asymbol **syms;
	bfd_vma pc;
	bfd_boolean found;
	const char *filename;
	const char *functionname;
	unsigned int line;
	unsigned int discriminator;
};

typedef void (*libatl_find_callback_t)(bfd_vma pc, const char *functionname, const char *filename, int line, void *data);

struct addr2line *addr2line_init(int pid);
bool addr2line_search(struct addr2line *ctx, bfd_vma pc, libatl_find_callback_t callback, void *data);
void addr2line_free(struct addr2line *ctx);

#endif
