#include "sysprobe-ebpf/types.h"
#include "sysprobe-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

static int sockops_write_header_options(struct bpf_sock_ops *ops)
{
	static u8 const TCP_OPT_PID_LEN = 8;
	struct tcp_options_header header;

	// (253, 254) are allocated to support experiments
	// ref: https://datatracker.ietf.org/doc/html/rfc6994#autoid-1
	header.kind = 253;
	header.length = TCP_OPT_PID_LEN;
	header.exid = 0xABCD;
	header.pid = 0;
	bpf_store_hdr_opt(ops, &header, TCP_OPT_PID_LEN, 0);
	return 0;
}

SEC("sockops")
int handle_socket_options(struct bpf_sock_ops *ops)
{
	switch (ops->op) {
	case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
		sockops_write_header_options(ops);
		break;
	}

	return 0;
}
