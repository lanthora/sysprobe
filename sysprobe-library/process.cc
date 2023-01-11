#include "sysprobe-library/process.h"
#include "sysprobe-library/addr2line.h"
#include <cstdio>
#include <proc/readproc.h>
#include <set>

void process_collector::scan_procfs()
{
	std::set<int> pids;

	// openproc 申请一块堆内存作为缓冲区,运行过程中不会释放, valgrind 会发现这个问题
	// https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=730460#20
	PROCTAB *proc = openproc(0);
	proc_t proc_info;
	memset(&proc_info, 0, sizeof(proc_info));

	while (readproc(proc, &proc_info) != NULL) {
		pids.insert(proc_info.tgid);
	}

	closeproc(proc);

	for (int pid : pids) {
		update_process_item(pid);
	}

	return;
}

int process_collector::copy_process_item(int new_pid, int old_pid)
{
	if (new_pid == old_pid) {
		return 0;
	}

	if (!process_map.contains(old_pid) || process_map.contains(new_pid)) {
		return 0;
	}

	process_map[new_pid] = process_map[old_pid];
	process_map[new_pid].pid = new_pid;

	return 0;
}

int process_collector::update_process_item(int pid)
{
	struct process_item item;

	item.pid = pid;
	item.addr2line_ctx = std::shared_ptr<struct addr2line>(addr2line_init(pid), [](struct addr2line *ctx) { addr2line_free(ctx); });

	process_map[pid] = item;
	return 0;
}

int process_collector::delete_process_item(int pid)
{
	process_map.erase(pid);
	return 0;
}

struct addr2line *process_collector::fetch_addr2line_ctx(int pid)
{
	std::map<pid_t, struct process_item>::iterator it = process_map.find(pid);
	if (it == process_map.end()) {
		return NULL;
	}
	return (*it).second.addr2line_ctx.get();
}

void process_collector::show_all_items()
{
	for (auto item : process_map) {
		printf("================================================================================\n");
		printf("pid:%d\n", item.second.pid);
		printf("addr2line ctx:%p\n", item.second.addr2line_ctx.get());
		printf("================================================================================\n\n");
	}
}
