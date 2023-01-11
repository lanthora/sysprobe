#include "sysprobe/addr2line.h"

static void find_address_in_section(bfd *abfd, asection *section, void *data)
{
	struct addr2line *ctx = (struct addr2line *)data;
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

static bfd_vma addr_start(int pid)
{
	FILE *maps = NULL;
	char buffer[1024];

	sprintf(buffer, "/proc/%d/maps", pid);
	maps = fopen(buffer, "rb");
	if (!maps) {
		return 0;
	}

	if (!fgets(buffer, sizeof(buffer), maps)) {
		fclose(maps);
		return 0;
	}

	fclose(maps);

	char *pos = strstr(buffer, "-");
	if (!pos) {
		fclose(maps);
		return 0;
	}
	*pos = '\0';
	return (bfd_vma)strtoll(buffer, NULL, 16);
}

struct addr2line *addr2line_init(int pid)
{
	char filename[4096];
	sprintf(filename, "/proc/%d/exe", pid);
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

	struct addr2line *ctx = (struct addr2line *)malloc(sizeof(struct addr2line));
	if (!ctx) {
		free(syms);
		bfd_close(abfd);
		return NULL;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->syms = syms;
	ctx->abfd = abfd;
	ctx->addr_start = addr_start(pid);

	// FIXME: 未启动 PIE 的情况下调整为 0, 需要有更好的方法判断是否启用 PIE
	if (ctx->addr_start == 0x400000) {
		ctx->addr_start = 0;
	}

	ctx->section = bfd_get_section_by_name(ctx->abfd, ".text");

	if ((bfd_section_flags(ctx->section) & SEC_ALLOC) == 0) {
		free(syms);
		bfd_close(abfd);
		free(ctx);
		return NULL;
	}

	return ctx;
}

bool addr2line_search(struct addr2line *ctx, bfd_vma pc, libatl_find_callback_t callback, void *data)
{
	if (!ctx)
		return FALSE;

	ctx->filename = NULL;
	ctx->functionname = NULL;
	ctx->line = 0;
	ctx->discriminator = 0;
	ctx->found = FALSE;
	ctx->pc = pc - ctx->addr_start;
	bfd_map_over_sections(ctx->abfd, find_address_in_section, ctx);
	if (callback) {
		callback(pc, ctx->functionname, ctx->filename, ctx->line, data);
	}

	return ctx->found;
}

void addr2line_free(struct addr2line *ctx)
{
	if (!ctx)
		return;

	free(ctx->syms);
	bfd_close(ctx->abfd);
	free(ctx);
}
