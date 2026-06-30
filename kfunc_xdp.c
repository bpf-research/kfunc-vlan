// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2026 Avinash Duduskar <avinash.duduskar@gmail.com> */
/* Attach the literal-test prog to a device, print its id for perf -b, wait for
 * SIGTERM, detach. Methodology: README.md / run_kfunc.sh.
 *
 * usage: kfunc_xdp <ifname> <mode> <working_set> <populate_count>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "kfunc_xdp.skel.h"

static volatile sig_atomic_t stop;
static int g_ifindex;
static __u32 g_flags;

static void on_term(int s) { (void)s; stop = 1; }

int main(int argc, char **argv)
{
	struct kfunc_xdp_bpf *skel;
	struct bpf_prog_info info = {};
	__u32 ilen = sizeof(info);
	int prog_fd, dmap, i, n = 0, mode, ws, popn;

	if (argc != 5) {
		fprintf(stderr,
			"usage: %s <ifname> <mode> <working_set> <populate_count>\n",
			argv[0]);
		return 2;
	}
	g_ifindex = if_nametoindex(argv[1]);
	if (!g_ifindex) {
		fprintf(stderr, "no such device: %s\n", argv[1]);
		return 1;
	}
	mode = atoi(argv[2]);
	ws = atoi(argv[3]);
	popn = atoi(argv[4]);

	skel = kfunc_xdp_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "open_and_load failed (kfunc in kernel BTF?)\n");
		return 1;
	}
	prog_fd = bpf_program__fd(skel->progs.drive);
	dmap = bpf_map__fd(skel->maps.devs);

	for (i = 1; i <= popn; i++) {
		char name[16];
		__u32 key = i - 1, ifx;

		snprintf(name, sizeof(name), "v%d", i);
		ifx = if_nametoindex(name);
		if (!ifx)
			break;
		bpf_map_update_elem(dmap, &key, &ifx, 0);
		n = i;
	}
	skel->bss->mode = mode;
	skel->bss->nr_devs = ws;
	skel->bss->idx = 0;

	/* native first, fall back to generic so this works on any veth */
	g_flags = XDP_FLAGS_DRV_MODE;
	if (bpf_xdp_attach(g_ifindex, prog_fd, g_flags, NULL)) {
		g_flags = XDP_FLAGS_SKB_MODE;
		if (bpf_xdp_attach(g_ifindex, prog_fd, g_flags, NULL)) {
			fprintf(stderr, "attach failed on %s\n", argv[1]);
			return 1;
		}
	}

	if (!bpf_prog_get_info_by_fd(prog_fd, &info, &ilen))
		printf("PROGID %u %s mode=%d ws=%d pop=%d\n", info.id,
		       g_flags == XDP_FLAGS_DRV_MODE ? "drv" : "skb",
		       mode, ws, n);
	fflush(stdout);

	signal(SIGTERM, on_term);
	signal(SIGINT, on_term);
	while (!stop)
		pause();

	bpf_xdp_detach(g_ifindex, g_flags, NULL);
	kfunc_xdp_bpf__destroy(skel);
	return 0;
}
