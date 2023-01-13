#include "sysprobe-ebpf/types.h"
#include "sysprobe-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

static inline void set_hdr_cb_flags(struct bpf_sock_ops *skops)
{
	bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
}

static inline void clear_hdr_cb_flags(struct bpf_sock_ops *skops)
{
	bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags & ~(BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG));
}

static inline int sockops_write_header_options(struct bpf_sock_ops *skops)
{
	struct tcp_options_header header;
	static const u8 TOA_LEN = 4 + sizeof(header.toa);

	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		set_hdr_cb_flags(skops);
		break;
	case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
		bpf_reserve_hdr_opt(skops, TOA_LEN, 0);
		break;
	case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
		header.kind = 254;
		header.length = TOA_LEN;
		header.exid = bpf_htons(TCP_OPTIONS_EXP_TYPE_TOA);
		header.toa.port = bpf_htons(skops->local_port);
		header.toa.ip = skops->local_ip4;
		bpf_store_hdr_opt(skops, &header, TOA_LEN, 0);
		clear_hdr_cb_flags(skops);
		break;
	}

	return 0;
}

SEC("sockops")
int handle_socket_options(struct bpf_sock_ops *skops)
{
	sockops_write_header_options(skops);
	return 1;
}
