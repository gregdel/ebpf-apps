#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define AF_INET		2
#define AF_INET6	10
#define ETH_ALEN	6
#define ETH_P_IP	0x0800
#define ETH_P_IPV6	0x86DD

SEC("xdp")
int forward(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;

	struct bpf_fib_lookup fib_params = {};

	if (eth + 1 > data_end)
		return XDP_ABORTED;

	switch (bpf_ntohs(eth->h_proto)) {
	case ETH_P_IP:
		iph = data + sizeof(struct ethhdr);
		if (iph + 1 > data_end)
			return XDP_ABORTED;

		fib_params.family      = AF_INET;
		fib_params.tos         = iph->tos;
		fib_params.l4_protocol = iph->protocol;
		fib_params.sport       = 0;
		fib_params.dport       = 0;
		fib_params.tot_len     = bpf_ntohs(iph->tot_len);
		fib_params.ipv4_src    = iph->saddr;
		fib_params.ipv4_dst    = iph->daddr;

		break;
	case ETH_P_IPV6:
		ip6h = data + sizeof(struct ethhdr);;
		if (ip6h + 1 > data_end)
			return XDP_ABORTED;

		// TODO: handle ipv6
		return XDP_PASS;
	default:
		return XDP_PASS;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	u32 flags = 0;
	int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);

	if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
		// Slow path, let the system perform the neighbor lookup
		return XDP_PASS;
	}

	if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
		// Drop everything that cannot be forwarded
		return XDP_DROP;
	}

	// Forward the packet
	__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
	return XDP_TX;
}

SEC("xdp_dummy")
int xdp_dummy_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
