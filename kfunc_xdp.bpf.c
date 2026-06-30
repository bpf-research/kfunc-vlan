// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2026 Avinash Duduskar <avinash.duduskar@gmail.com> */
/* literal-test prog: attached to a veth, calls the kfunc per frame, drops it.
 * mode 1 adds the kfunc; mode1-mode0 is the real-path cost. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_DEVS 4096

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_DEVS);
	__type(key, __u32);
	__type(value, __u32);
} devs SEC(".maps");

__u32 nr_devs = 0;
__u32 mode = 0;		/* 0 = fib_lookup only, 1 = + kfunc */
__u64 idx = 0;
__u64 pkts = 0;		/* real frames seen, for a liveness sanity check */

extern int bpf_xdp_egress_dev(struct xdp_md *ctx, __u32 ifindex) __ksym;

SEC("xdp")
int drive(struct xdp_md *ctx)
{
	struct bpf_fib_lookup p = {};
	__u32 i, *ifx;

	pkts++;
	if (!nr_devs)
		return XDP_DROP;

	i = idx++ % nr_devs;
	ifx = bpf_map_lookup_elem(&devs, &i);
	if (!ifx)
		return XDP_DROP;

	p.family = 2;		/* AF_INET */
	p.ifindex = *ifx;
	bpf_fib_lookup(ctx, &p, sizeof(p), 0);

	if (mode)
		bpf_xdp_egress_dev(ctx, *ifx);

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
