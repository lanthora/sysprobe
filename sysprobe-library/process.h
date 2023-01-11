#ifndef SYSPROBE_PROCESS_H
#define SYSPROBE_PROCESS_H

#include "sysprobe-library/addr2line.h"
#include <map>
#include <memory>

// 用户态维护的与进程相关的数据结构.在 update_process_item 中更新.
// 未来可以用来保存当前进程挂载的 uprobe 的 hook 状态和偏移等信息.
struct process_item {
	pid_t pid;
	std::shared_ptr<struct addr2line> addr2line_ctx;
};

class process_collector {
    public:
	// 扫描 /proc 目录, 尽可能填充 process_collector
	void scan_procfs();

	// 新进程创建时调用,用父进程信息填充子进程,适用于仅 fork 但不 execve 的进程,例如 nginx 的工作进程
	int copy_process_item(int new_pid, int old_pid);

	// execve 系统调用刷新内存,进程信息已经变更,无法直接使用 fork 后的信息,需要重新获取
	int update_process_item(int pid);

	// 进程退出时调用,清理进程信息
	int delete_process_item(int pid);

	// 根据进程号那 addr2line 上下文
	struct addr2line *fetch_addr2line_ctx(int pid);

	// 打印收集的信息,用于调试
	void show_all_items();

    private:
	// 保存系统中的所有进程
	std::map<pid_t, struct process_item> process_map;
};

#endif
