// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2026 Avinash Duduskar <avinash.duduskar@gmail.com> */
/* AF_PACKET flooder: blast a fixed 64-byte frame out an interface until killed,
 * to drive the peer's XDP prog. Frame content does not matter, only arrival.
 *
 * usage: pkt_send <ifname> <core>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define BATCH 64	/* frames per sendmmsg syscall */

int main(int argc, char **argv)
{
	unsigned char frame[64];
	struct sockaddr_ll sll = {};
	cpu_set_t set;
	int fd, ifindex, core;
	unsigned long sent = 0;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <ifname> <core>\n", argv[0]);
		return 2;
	}
	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		fprintf(stderr, "no such device: %s\n", argv[1]);
		return 1;
	}
	core = atoi(argv[2]);
	CPU_ZERO(&set);
	CPU_SET(core, &set);
	if (sched_setaffinity(0, sizeof(set), &set))
		perror("setaffinity");

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	/* dst MAC ff:.., src 02:.., ethertype IPv4; rest is a zeroed IPv4-ish
	 * payload. XDP runs before any L2/L3 validation, so this is enough. */
	memset(frame, 0, sizeof(frame));
	memset(frame, 0xff, 6);
	frame[6] = 0x02;
	frame[12] = 0x08; frame[13] = 0x00;	/* ETH_P_IP */
	frame[14] = 0x45;			/* IPv4, IHL 5 */

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	sll.sll_halen = 6;
	memset(sll.sll_addr, 0xff, 6);

	/* batch with sendmmsg so the sender is not the bottleneck: a single-frame
	 * sendto loop tops out near 0.4 Mpps, far below the XDP prog's rate, so the
	 * kfunc cost would not show in pps. 64 frames/syscall pushes multi-Mpps. */
	struct mmsghdr msgs[BATCH];
	struct iovec iov[BATCH];
	int i;

	memset(msgs, 0, sizeof(msgs));
	for (i = 0; i < BATCH; i++) {
		iov[i].iov_base = frame;
		iov[i].iov_len = sizeof(frame);
		msgs[i].msg_hdr.msg_iov = &iov[i];
		msgs[i].msg_hdr.msg_iovlen = 1;
		msgs[i].msg_hdr.msg_name = &sll;
		msgs[i].msg_hdr.msg_namelen = sizeof(sll);
	}

	for (;;) {
		int n = sendmmsg(fd, msgs, BATCH, 0);

		if (n > 0)
			sent += n;
		if ((sent & 0xffffff) == 0)
			fprintf(stderr, "\rsent %lu", sent);
	}
	return 0;
}
