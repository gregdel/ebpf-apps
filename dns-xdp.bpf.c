#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

struct bpf_map_def SEC("maps") proto_hash = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(u64),
        .max_entries = 1024,
};

static __always_inline
int parse_ipv4(void *data, u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;

	return iph->protocol;
}

static __always_inline
int parse_ipv6(void *data, u64 nh_off, void *data_end)
{
	struct ipv6hdr *ip6h = data + nh_off;

	if (ip6h + 1 > data_end)
		return 0;

	return ip6h->nexthdr;
}

SEC("xdp")
int xdp_drop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u64 *value;
	u16 h_proto;
	u64 nh_off;
	u32 ipproto;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	h_proto = eth->h_proto;

	if (h_proto == bpf_htons(ETH_P_IP))
		ipproto = parse_ipv4(data, nh_off, data_end);
	else if (h_proto == bpf_htons(ETH_P_IPV6))
		ipproto = parse_ipv6(data, nh_off, data_end);
	else
		ipproto = 0;

	value = bpf_map_lookup_elem(&proto_hash, &ipproto);
	if (value) {
		*value += 1;
	} else {
		value = 1;
		bpf_map_update_elem(&proto_hash, &ipproto, &value, BPF_NOEXIST);
	}

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
