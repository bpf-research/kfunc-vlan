// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2026 Avinash Duduskar <avinash.duduskar@gmail.com> */
/* micro-bench prog: both modes do bpf_fib_lookup(); mode 1 adds the kfunc. */
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
__u32 mode = 0;		/* 0 = fib_lookup only (~v5), 1 = fib_lookup + kfunc */
__u64 idx = 0;
int fib_ret = 0;
int egr_ret = 0;

extern int bpf_xdp_egress_dev(struct xdp_md *ctx, __u32 ifindex) __ksym;

SEC("xdp")
int drive(struct xdp_md *ctx)
{
	struct bpf_fib_lookup p = {};
	__u32 i, *ifx;

	if (!nr_devs)
		return XDP_PASS;

	i = idx++ % nr_devs;
	ifx = bpf_map_lookup_elem(&devs, &i);
	if (!ifx)
		return XDP_PASS;

	p.family = 2;		/* AF_INET */
	p.ifindex = *ifx;
	fib_ret = bpf_fib_lookup(ctx, &p, sizeof(p), 0);

	if (mode)
		egr_ret = bpf_xdp_egress_dev(ctx, *ifx);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
