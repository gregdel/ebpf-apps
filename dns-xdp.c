#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "dns-xdp.skel.h"

const char *dev = "wlp58s0";

static volatile bool exiting = false;

static void sig_handler(int sig) {
	exiting = true;
}

static void bump_memlock_rlimit(void) {
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

int main() {
	struct dns_xdp_bpf *skel;
	int err = 0;

	__u32 ifindex = if_nametoindex(dev);
	if (errno == ENODEV) {
		fprintf(stderr, "Interface %s not found\n", dev);
		return 1;
	}
	printf("Found interface index of %s: %d\n", dev, ifindex);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	skel = dns_xdp_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open skeleton\n");
		return 1;
	}

	if (!skel->progs.xdp_drop) {
		fprintf(stderr, "Is the program loaded ?\n");
		goto cleanup;
	}

	err = dns_xdp_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load program\n");
		return 1;
	}

	/* Attach xdp program */
	err = dns_xdp_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	int map_fd = bpf_map__fd(skel->maps.proto_hash);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get the map fd\n");
		goto cleanup;
	}

	int program_fd = bpf_program__fd(skel->progs.xdp_drop);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get the program fd\n");
		goto cleanup;
	}

	__u32 xdp_flags =
		XDP_FLAGS_UPDATE_IF_NOEXIST &
		XDP_FLAGS_REPLACE &
		XDP_FLAGS_SKB_MODE;

	err = bpf_set_link_xdp_fd(ifindex, program_fd, xdp_flags);
	if (err < 0) {
		fprintf(stderr, "Failed to set xdp link\n");
		goto cleanup;
	}

	printf("Map fd: %d\n", map_fd);
	printf("Program fd: %d\n", program_fd);

	while (!exiting) {
		const char *keys[] = {"TCP", "UDP", "ICMP"};
		const __u32 protos[] = {IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP};

		const size_t max = sizeof(keys)/sizeof(char*);
		__u64 value;
		for (int i = 0; i < max; i++) {
			if (bpf_map_lookup_elem(map_fd, &protos[i], &value) < 0)
				value = 0;

			printf("%s : %lld\n", keys[i], value);
		}

		sleep(1);
	}

cleanup:
	/* Clean up */
	if (program_fd > 0) {
		printf("Detaching stuff\n");
		if (bpf_set_link_xdp_fd(ifindex, -1, 0) < 0) {
			fprintf(stderr, "Failed to dettach xdp program\n");
		}
	}

	dns_xdp_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
