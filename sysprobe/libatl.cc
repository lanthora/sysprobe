#include "sysprobe/libatl.h"

static void find_address_in_section(bfd *abfd, asection *section, void *data)
{
	struct libatl_context *ctx = (struct libatl_context *)data;
	if (ctx->found)
		return;
	if ((bfd_section_flags(section) & SEC_ALLOC) == 0)
		return;
	bfd_vma vma = bfd_section_vma(section);
	if (ctx->pc < vma)
		return;
	bfd_size_type size = bfd_section_size(section);
	if (ctx->pc >= vma + size)
		return;
	ctx->found = bfd_find_nearest_line_discriminator(abfd, section, ctx->syms, ctx->pc - vma, &ctx->filename, &ctx->functionname, &ctx->line,
							 &ctx->discriminator);
}

struct libatl_context *libatl_init(const char *filename)
{
	bfd *abfd = bfd_openr(filename, NULL);
	if (!abfd)
		return NULL;

	abfd->flags |= BFD_DECOMPRESS;
	if (!bfd_check_format(abfd, bfd_object)) {
		bfd_close(abfd);
		return NULL;
	}

	if (!(bfd_get_file_flags(abfd) & HAS_SYMS)) {
		bfd_close(abfd);
		return NULL;
	}

	long storage = bfd_get_symtab_upper_bound(abfd);
	if (storage <= 0) {
		bfd_close(abfd);
		return NULL;
	}

	asymbol **syms = (asymbol **)malloc(storage);
	if (!syms) {
		bfd_close(abfd);
		return NULL;
	}

	if (bfd_canonicalize_symtab(abfd, syms) <= 0) {
		free(syms);
		bfd_close(abfd);
		return NULL;
	}

	struct libatl_context *ctx = (struct libatl_context *)malloc(sizeof(struct libatl_context));
	if (!ctx) {
		free(syms);
		bfd_close(abfd);
		return NULL;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->syms = syms;
	ctx->abfd = abfd;
	return ctx;
}

bool libatl_find(struct libatl_context *ctx, bfd_vma pc, libatl_find_callback_t callback, void *data)
{
	if (!ctx)
		return FALSE;

	ctx->found = FALSE;
	ctx->pc = pc;
	bfd_map_over_sections(ctx->abfd, find_address_in_section, ctx);
	if (ctx->found && callback) {
		callback(pc, ctx->functionname, ctx->filename, ctx->line, data);
	}

	return ctx->found;
}

void libatl_free(struct libatl_context *ctx)
{
	free(ctx->syms);
	bfd_close(ctx->abfd);
	free(ctx);
}
