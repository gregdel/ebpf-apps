#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_ARP 0x0806
#define ETH_ALEN 6

const unsigned char mac_a[ETH_ALEN]  = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x0a };
const unsigned char mac_b[ETH_ALEN]  = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x0b };
const unsigned char mac_fw[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0xff };

static __always_inline
int cmp(unsigned const char a[ETH_ALEN], unsigned const char b[ETH_ALEN])
{
	for (int i = 1; i < ETH_ALEN; i++)
		if (a[i] != b[i])
			return -1;

	return 0;
}

SEC("xdp")
int forward(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if (eth + 1 > data_end)
		return XDP_PASS;

	// Let ARP packets go through
	if (bpf_ntohs(eth->h_proto) == ETH_P_ARP) {
		return XDP_PASS;
	}

	// Only work with the packet for us
	if (cmp(eth->h_dest, mac_fw) == -1) {
		return XDP_DROP;
	}

	// Rewrite the headers
	if (cmp(eth->h_source, mac_a) != -1)
		__builtin_memcpy(eth->h_dest, mac_b, ETH_ALEN);
	if (cmp(eth->h_source, mac_b) != -1)
		__builtin_memcpy(eth->h_dest, mac_a, ETH_ALEN);
	__builtin_memcpy(eth->h_source, mac_fw, ETH_ALEN);

	return XDP_TX;
}

SEC("xdp_dummy")
int xdp_dummy_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
