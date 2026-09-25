// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_arena_common.h"
#include "arena_kvm_shared.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE | BPF_F_ARENA_NO_FREE);
	__uint(max_entries, 1);
} arena SEC(".maps");

volatile __u32 signal_offset;

SEC("syscall")
int allocate(void *ctx)
{
	struct signal_page __arena *page;

	page = bpf_arena_alloc_pages(&arena, NULL, 1, ARENA_KVM_NODE, 0);
	if (!page)
		return 1;
	signal_offset = (__u32)((__u64)page - (__u64)arena_base(&arena));
	page->ready = GUEST_READY;
	return 0;
}

SEC("syscall")
int probe_free(void *ctx)
{
	struct signal_page __arena *page =
		(struct signal_page __arena *)((char __arena *)arena_base(&arena) +
					     signal_offset);

	bpf_arena_free_pages(&arena, page, 1);
	return page->ready == GUEST_READY ? 0 : 1;
}

SEC("syscall")
int exchange(void *ctx)
{
	struct signal_page __arena *page =
		(struct signal_page __arena *)((char __arena *)arena_base(&arena) +
					     signal_offset);
	__u64 seq = page->h2g_seq;
	__u64 payload;

	if ((seq != 1 && seq != 2) || page->g2h_seq == seq)
		return 1;
	payload = page->h2g_payload;
	if (seq == 1 && payload != HOST_FIRST)
		return 2;
	if (seq == 2 && payload != HOST_SECOND)
		return 3;
	page->g2h_payload = seq == 1 ? GUEST_FIRST : GUEST_SECOND;
	page->g2h_seq = seq;
	return 0;
}

SEC("syscall")
int complete(void *ctx)
{
	struct signal_page __arena *page =
		(struct signal_page __arena *)((char __arena *)arena_base(&arena) +
					     signal_offset);

	return page->h2g_seq == 3 ? 0 : 1;
}

char _license[] SEC("license") = "GPL";
