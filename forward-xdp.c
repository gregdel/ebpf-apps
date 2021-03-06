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
#include "forward-xdp.skel.h"

const char *dev = "out";

static volatile bool exiting = false;

static void sig_handler(int sig) {
	exiting = true;
}

int main() {
	struct forward_xdp_bpf *skel;
	int err = 0;

	__u32 ifindex = if_nametoindex(dev);
	if (errno == ENODEV) {
		fprintf(stderr, "Interface %s not found\n", dev);
		return 1;
	}
	printf("Found interface index of %s: %d\n", dev, ifindex);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = forward_xdp_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open skeleton\n");
		return 1;
	}

	if (!skel->progs.forward) {
		fprintf(stderr, "Is the program loaded ?\n");
		goto cleanup;
	}

	err = forward_xdp_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load program\n");
		return 1;
	}

	/* Attach xdp program */
	err = forward_xdp_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	int program_fd = bpf_program__fd(skel->progs.forward);
	if (program_fd < 0) {
		fprintf(stderr, "Failed to get the program fd\n");
		goto cleanup;
	}

	__u32 xdp_flags =
		XDP_FLAGS_UPDATE_IF_NOEXIST &
		XDP_FLAGS_REPLACE &
		XDP_FLAGS_SKB_MODE;

	err = bpf_xdp_attach(ifindex, program_fd, xdp_flags, NULL);
	if (err < 0) {
		fprintf(stderr, "Failed to set xdp link\n");
		goto cleanup;
	}

	printf("Program fd: %d\n", program_fd);

	while (!exiting) {
		sleep(1);
	}

cleanup:
	if (program_fd > 0) {
		printf("Detaching stuff\n");
		if (bpf_xdp_detach(ifindex, 0, NULL) < 0) {
			fprintf(stderr, "Failed to dettach xdp program\n");
		}
	}

	forward_xdp_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
