#include "sysprobe-library/process.h"

static void stack_trace_callback(bfd_vma pc, const char *functionname, const char *filename, int line, void *data)
{
	int idx = *(int *)data;
	printf("%p at %s in %s:%d\n", (void *)pc, functionname, filename, line);
}

int main()
{
	struct addr2line *ctx;
	class process_collector collector;
	collector.scan_procfs();

	ctx = collector.fetch_addr2line_ctx(getpid());

	bfd_vma pc = (bfd_vma)stack_trace_callback;
	assert(addr2line_search(ctx, pc, stack_trace_callback, NULL));

	return 0;
}
