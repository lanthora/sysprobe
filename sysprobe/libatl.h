#ifndef SYSPROBE_LIBATL_H
#define SYSPROBE_LIBATL_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PACKAGE "libaddr2line"
#define PACKAGE_VERSION "0.0.0"
#include <bfd.h>

struct libatl_context {
	bfd *abfd;
	asymbol **syms;
	bfd_vma pc;
	bfd_boolean found;
	const char *filename;
	const char *functionname;
	unsigned int line;
	unsigned int discriminator;
};

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*libatl_find_callback_t)(bfd_vma pc, const char *functionname, const char *filename, int line, void *data);

struct libatl_context *libatl_init(const char *filename);
bool libatl_find(struct libatl_context *ctx, bfd_vma pc, libatl_find_callback_t callback, void *data);
void libatl_free(struct libatl_context *ctx);

#ifdef __cplusplus
}
#endif

#endif
