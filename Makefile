# SPDX-License-Identifier: GPL-2.0-only
# Build the bpf_xdp_egress_dev cost bench on your own machine.
#
# Requires: clang, gcc/cc, bpftool, libbpf (dev), and a kernel whose vmlinux BTF
# exports bpf_xdp_egress_dev (the patched/merged kernel). vmlinux.h is generated
# from THIS machine's running kernel, so the build tracks your kernel, not mine.
#
#   make            build everything
#   make clean      remove built artifacts
#
# Run on the box (root): ./run_kfunc.sh <output-parent-dir>
# Analyse on any host:   python3 analyze_kfunc.py <output-dir>

CLANG      ?= clang
CC         ?= cc
BPFTOOL    ?= bpftool
CFLAGS     ?= -O2 -Wall
BPF_CFLAGS ?= -O2 -g -Wall -target bpf
LDLIBS     := -lbpf -lelf -lz

BINS  := kfunc_drive kfunc_xdp pkt_send controls/chase
SKELS := kfunc_drive.skel.h kfunc_xdp.skel.h
OBJS  := kfunc_drive.bpf.o kfunc_xdp.bpf.o

all: $(BINS)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@ -I.

%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

kfunc_drive: kfunc_drive.c kfunc_drive.skel.h
	$(CC) $(CFLAGS) -I. $< $(LDLIBS) -o $@

kfunc_xdp: kfunc_xdp.c kfunc_xdp.skel.h
	$(CC) $(CFLAGS) -I. $< $(LDLIBS) -o $@

pkt_send: pkt_send.c
	$(CC) $(CFLAGS) $< -o $@

controls/chase: controls/chase.c
	$(CC) $(CFLAGS) $< -lrt -o $@

clean:
	rm -f $(BINS) $(SKELS) $(OBJS) vmlinux.h

.PHONY: all clean
