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

static __always_inline
int parse_ethernet(void *data, u64 nh_off, void *data_end)
{
	struct ethhdr *eth = data;
	if (eth + 1 > data_end)
		return -1;

	return bpf_ntohs(eth->h_proto);
}

static __always_inline
int parse_dns(void *data, u64 nh_off, void *data_end)
{
	struct udphdr *udp = data + nh_off;
	if (udp + 1 > data_end)
		return -1;

	return 0;
}

SEC("xdp")
int xdp_app(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u64 *value = 0;
	u64 nh_off = 0;

	u16 h_proto = parse_ethernet(data, nh_off, data_end);
	if (h_proto < 0)
		return XDP_PASS;

	nh_off += sizeof(struct ethhdr);
	if (data + nh_off > data_end)
		return XDP_ABORTED;

	u32 ipproto;
	switch (h_proto) {
	case ETH_P_IP:
		ipproto = parse_ipv4(data, nh_off, data_end);
		nh_off += sizeof(struct iphdr);
		break;
	case ETH_P_IPV6:
		ipproto = parse_ipv6(data, nh_off, data_end);
		nh_off += sizeof(struct ipv6hdr);
		break;
	default:
		ipproto = 0;
	}

	if (data + nh_off > data_end)
		return XDP_ABORTED;

	/* if (ipproto != IPPROTO_UDP) { */
	/* 	return XDP_PASS; */
	/* } */

	/* parse_dns(data, nh_off, data_end); */

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
