// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2026 Avinash Duduskar <avinash.duduskar@gmail.com> */
/* PROG_TEST_RUN micro-bench for bpf_xdp_egress_dev; mode1-mode0 is the kfunc
 * cost. Prints raw per-run CSV. Sweeps, controls and analysis: run_kfunc.sh.
 *
 * usage: kfunc_drive footprint | chain [K]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "kfunc_drive.skel.h"

#define MAX_DEVS 4096
#define CORE	 6
#define R	 11		/* paired runs per cell */
#define REP	 200000		/* iterations per run */
#define WARMUP	 50000

static int perf_open(unsigned type, unsigned long long config)
{
	struct perf_event_attr a = {
		.type = type, .config = config, .size = sizeof(a),
		.disabled = 1, .exclude_hv = 1,
		.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED |
			       PERF_FORMAT_TOTAL_TIME_RUNNING,
	};
	return syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
}

/* Raw count since the last reset. We do NOT scale by enabled/running: IOC_RESET
 * zeroes the count but not the time fields, so the lifetime ratio is not
 * per-window and would mis-scale. With three counters (well under the 6 core
 * PMCs) and nmi_watchdog off the events never multiplex, so the raw count is
 * exact; the run's isolation read-back records that the environment held. */
static double rd(int fd)
{
	struct { unsigned long long val, ena, run; } v = {};
	if (fd < 0 || read(fd, &v, sizeof(v)) != sizeof(v))
		return 0;
	return (double)v.val;
}

/* fill the map with the first `count` vN ifindexes; return how many existed */
static int populate(int dmap, int count)
{
	int i, n = 0;

	for (i = 1; i <= count && i <= MAX_DEVS; i++) {
		char name[16];
		__u32 key = i - 1, ifx;

		snprintf(name, sizeof(name), "v%d", i);
		ifx = if_nametoindex(name);
		if (!ifx)
			break;
		bpf_map_update_elem(dmap, &key, &ifx, 0);
		n = i;
	}
	return n;
}

static int probe_pop(void)
{
	int i, n = 0;
	char name[16];

	for (i = 1; i <= MAX_DEVS; i++) {
		snprintf(name, sizeof(name), "v%d", i);
		if (!if_nametoindex(name))
			break;
		n = i;
	}
	return n;
}

static void cell(struct kfunc_drive_bpf *skel, int prog_fd, int cyc, int dram,
		 int l2, const char *sweep, int pop, int ws)
{
	char data[64] = {};
	int r, m;

	for (r = 0; r < R; r++) {
		for (m = 0; m <= 1; m++) {
			LIBBPF_OPTS(bpf_test_run_opts, o,
				    .data_in = data, .data_size_in = sizeof(data));
			double c, df, l2m, ns;

			skel->bss->mode = m;
			skel->bss->nr_devs = ws;
			skel->bss->idx = 0;

			o.repeat = WARMUP;
			bpf_prog_test_run_opts(prog_fd, &o);

			ioctl(cyc, PERF_EVENT_IOC_RESET, 0);
			ioctl(dram, PERF_EVENT_IOC_RESET, 0);
			ioctl(l2, PERF_EVENT_IOC_RESET, 0);
			ioctl(cyc, PERF_EVENT_IOC_ENABLE, 0);
			ioctl(dram, PERF_EVENT_IOC_ENABLE, 0);
			ioctl(l2, PERF_EVENT_IOC_ENABLE, 0);
			o.repeat = REP;
			bpf_prog_test_run_opts(prog_fd, &o);
			ioctl(cyc, PERF_EVENT_IOC_DISABLE, 0);
			ioctl(dram, PERF_EVENT_IOC_DISABLE, 0);
			ioctl(l2, PERF_EVENT_IOC_DISABLE, 0);

			c = rd(cyc) / REP;	/* perf counter is total over REP */
			df = rd(dram) / REP;	/* DRAM fills = L3 miss->DRAM */
			l2m = rd(l2) / REP;	/* L2 misses */
			ns = (double)o.duration; /* kernel already divides by repeat */
			printf("CSV %s,%d,%d,%d,%d,%.2f,%.4f,%.6f,%.6f,%.4f\n",
			       sweep, pop, ws, r, m, c, ns, df, l2m,
			       ns ? c / ns : 0);
			fflush(stdout);
		}
	}
}

int main(int argc, char **argv)
{
	static const int Ns[] = { 1, 2, 4, 8, 16, 32, 64, 128, 256,
				  512, 1024, 2048, 4094 };
	cpu_set_t set;
	struct kfunc_drive_bpf *skel;
	int prog_fd, dmap, cyc, dram, l2, pop, k;
	int chain = 0, K = 8;
	int core = getenv("BENCH_CORE") ? atoi(getenv("BENCH_CORE")) : CORE;
	/* Zen4 raw event configs (perf type 4 = RAW): dram_io_near (L3 miss->DRAM)
	 * and l2 ic_dc_miss_in_l2. Override per-arch via env. */
	unsigned long long dcfg = getenv("BENCH_DRAM_CFG") ?
		strtoull(getenv("BENCH_DRAM_CFG"), NULL, 16) : 0x844;
	unsigned long long l2cfg = getenv("BENCH_L2_CFG") ?
		strtoull(getenv("BENCH_L2_CFG"), NULL, 16) : 0x964;

	if (argc < 2 || (strcmp(argv[1], "footprint") &&
			 strcmp(argv[1], "chain"))) {
		fprintf(stderr, "usage: %s footprint | chain [K]\n", argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "chain")) {
		chain = 1;
		if (argc >= 3)
			K = atoi(argv[2]);
	}

	CPU_ZERO(&set);
	CPU_SET(core, &set);
	if (sched_setaffinity(0, sizeof(set), &set))
		perror("setaffinity");

	skel = kfunc_drive_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "open_and_load failed (kfunc in kernel BTF?)\n");
		return 1;
	}
	prog_fd = bpf_program__fd(skel->progs.drive);
	dmap = bpf_map__fd(skel->maps.devs);

	pop = probe_pop();
	fprintf(stderr, "population %d devs\n", pop);

	cyc = perf_open(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
	dram = perf_open(PERF_TYPE_RAW, dcfg);	/* L3 miss -> DRAM */
	l2 = perf_open(PERF_TYPE_RAW, l2cfg);	/* L2 misses */
	if (cyc < 0)
		fprintf(stderr, "cycles counter unavailable: %m\n");
	if (dram < 0)
		fprintf(stderr, "dram-fill counter unavailable: %m\n");
	if (l2 < 0)
		fprintf(stderr, "l2-miss counter unavailable: %m\n");

	if (chain) {
		/* hot set = first K; population is whatever the shell built */
		int n = populate(dmap, K);

		if (n < K)
			fprintf(stderr, "only %d devs, K capped\n", n);
		cell(skel, prog_fd, cyc, dram, l2, "chain", pop, n);
	} else {
		int n = populate(dmap, MAX_DEVS);

		for (k = 0; k < (int)(sizeof(Ns) / sizeof(Ns[0])); k++) {
			if (Ns[k] > n)
				break;
			cell(skel, prog_fd, cyc, dram, l2, "footprint", n, Ns[k]);
		}
	}

	kfunc_drive_bpf__destroy(skel);
	return 0;
}
