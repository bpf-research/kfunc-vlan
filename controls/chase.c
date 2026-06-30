// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Avinash Duduskar <avinash.duduskar@gmail.com>
// chase.c: a random pointer-chase reporting DRAM access latency. Used here as the
// DRAM-latency control, sampled across a run to confirm the memory subsystem
// stayed stable.
//
// A 256 MiB arena, a shuffled permutation of cache lines, one dependent load per
// step, prefetchers off at the box level. Options:
//   --pages thp|4k   page backing via madvise()
//   --cpu N          pin to a core
//   --samples K      number of timed passes
//
// Reports ns/access and the arena's actual AnonHugePages (from smaps), so the
// page backing is confirmed, not assumed: madvise is advisory, and a kernel with
// THP disabled gives 4 KiB even under MADV_HUGEPAGE.
//
// Build: gcc -O2 -o chase chase.c -lrt
// Use:   ./chase --cpu 0 --pages thp --samples 2

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/mman.h>

#define ARRAY_MB      256
#define ARRAY_BYTES   ((size_t)ARRAY_MB * 1024 * 1024)
#define CACHELINE     64
#define STRIDE        (CACHELINE / sizeof(uint64_t))
#define CHASE_ITERS   (10 * 1000 * 1000)
#define WARMUP_ITERS  (1 * 1000 * 1000)

static void shuffle(uint64_t *a, uint64_t n)
{
	for (uint64_t i = n - 1; i > 0; i--) {
		uint64_t j = (uint64_t)rand() % (i + 1);
		uint64_t t = a[i]; a[i] = a[j]; a[j] = t;
	}
}

// Report AnonHugePages (KiB) for the smaps mapping that contains `addr`.
static long anon_hugepages_kb(void *addr)
{
	FILE *f = fopen("/proc/self/smaps", "r");
	if (!f)
		return -1;
	char line[256];
	unsigned long lo = 0, hi = 0, target = (unsigned long)addr;
	int in_region = 0;
	long ahp = -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx", &lo, &hi) == 2) {
			in_region = (target >= lo && target < hi);
			continue;
		}
		if (in_region && strncmp(line, "AnonHugePages:", 14) == 0) {
			sscanf(line + 14, "%ld", &ahp);
			break;
		}
	}
	fclose(f);
	return ahp;
}

int main(int argc, char **argv)
{
	int cpu = 0, want_4k = 0, samples = 5;
	static struct option opts[] = {
		{"cpu",     required_argument, 0, 'c'},
		{"pages",   required_argument, 0, 'p'},
		{"samples", required_argument, 0, 's'},
		{0, 0, 0, 0}
	};
	int o;
	while ((o = getopt_long(argc, argv, "c:p:s:", opts, NULL)) != -1) {
		switch (o) {
		case 'c': cpu = atoi(optarg); break;
		case 'p': want_4k = (strcmp(optarg, "4k") == 0); break;
		case 's': samples = atoi(optarg); break;
		default:
			fprintf(stderr, "usage: %s --cpu N --pages thp|4k [--samples K]\n", argv[0]);
			return 2;
		}
	}

	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set) != 0) {
		perror("sched_setaffinity");
		return 1;
	}

	// 2 MiB-align the arena: an unaligned anon mapping cannot take a hugepage at
	// fault time, so without this the THP run silently stays 4 KiB and the
	// intervention shows "no effect" for the wrong reason. Over-map by one
	// hugepage and align the start.
	size_t HUGE = 2UL * 1024 * 1024;
	void *raw = mmap(NULL, ARRAY_BYTES + HUGE, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (raw == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	void *arena = (void *)(((uintptr_t)raw + HUGE - 1) & ~(HUGE - 1));
	// Advisory: request or forbid transparent hugepages for this region.
	if (madvise(arena, ARRAY_BYTES, want_4k ? MADV_NOHUGEPAGE : MADV_HUGEPAGE) != 0)
		perror("madvise (continuing)");

	uint64_t *a = (uint64_t *)arena;
	uint64_t n_lines = ARRAY_BYTES / sizeof(uint64_t) / STRIDE;
	uint64_t *idx = calloc(n_lines, sizeof(uint64_t));
	if (!idx) { perror("calloc"); return 1; }

	memset(arena, 0, ARRAY_BYTES);          // fault in every page with the chosen backing
	for (uint64_t i = 0; i < n_lines; i++)
		idx[i] = i;
	srand(42);
	shuffle(idx, n_lines);
	for (uint64_t i = 0; i < n_lines - 1; i++)
		a[idx[i] * STRIDE] = idx[i + 1] * STRIDE;
	a[idx[n_lines - 1] * STRIDE] = idx[0] * STRIDE;
	free(idx);

	long ahp = anon_hugepages_kb(arena);
	printf("{\"cpu\": %d, \"pages\": \"%s\", \"array_mb\": %d, "
	       "\"anon_hugepages_kb\": %ld, \"thp_backed\": %s, \"samples\": [",
	       cpu, want_4k ? "4k" : "thp", ARRAY_MB, ahp,
	       (ahp > ARRAY_MB * 1024 / 2) ? "true" : "false");

	volatile uint64_t sink = 0;
	double best = 1e30, sum = 0;
	for (int s = 0; s < samples; s++) {
		uint64_t p = 0;
		for (uint64_t i = 0; i < WARMUP_ITERS; i++)
			p = a[p];
		struct timespec t0, t1;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (uint64_t i = 0; i < CHASE_ITERS; i++)
			p = a[p];
		clock_gettime(CLOCK_MONOTONIC, &t1);
		sink += p;
		double ns = ((t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec))
			    / (double)CHASE_ITERS;
		printf("%s%.2f", s ? ", " : "", ns);
		if (ns < best) best = ns;
		sum += ns;
	}
	printf("], \"min_ns\": %.2f, \"mean_ns\": %.2f}\n", best, sum / samples);
	(void)sink;
	munmap(raw, ARRAY_BYTES + HUGE);
	return 0;
}
