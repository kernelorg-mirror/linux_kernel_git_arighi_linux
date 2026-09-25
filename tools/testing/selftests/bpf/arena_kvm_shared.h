/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARENA_KVM_SHARED_H
#define ARENA_KVM_SHARED_H

#define ARENA_KVM_PAGES 512
#define ARENA_KVM_BYTES (ARENA_KVM_PAGES * 4096)
#define ARENA_KVM_NODE 1

#define GUEST_READY 0x4152454e414b564dULL
#define HOST_FIRST 0x123456789abcdef0ULL
#define GUEST_FIRST 0xfedcba9876543210ULL
#define HOST_SECOND 0x1020304050607080ULL
#define GUEST_SECOND 0x8070605040302010ULL

struct signal_page {
	volatile unsigned long long ready;
	volatile unsigned long long h2g_payload;
	volatile unsigned long long h2g_seq;
	volatile unsigned long long g2h_payload;
	volatile unsigned long long g2h_seq;
};

#endif
