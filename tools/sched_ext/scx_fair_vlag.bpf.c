// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 *
 * Reset virtual lag when fair places a task on a runqueue.
 */
#include <scx/fair.bpf.h>

char _license[] SEC("license") = "GPL";

struct scx_fair_vlag_stats {
	u64 nr_select;
	u64 nr_override;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct scx_fair_vlag_stats));
	__uint(max_entries, 1);
} stats SEC(".maps");

static __always_inline struct scx_fair_vlag_stats *get_stats(void)
{
	u32 idx = 0;

	return bpf_map_lookup_elem(&stats, &idx);
}

SEC("struct_ops/fair_select_vlag")
s64 BPF_PROG(scx_fair_vlag_select_vlag, struct task_struct *p,
	     const struct fair_ext_vlag_ctx *state)
{
	struct scx_fair_vlag_stats *stats;

	stats = get_stats();
	if (stats)
		stats->nr_select++;

	if (!(state->flags & FAIR_EXT_VLAG_PLACE))
		return state->vlag;

	if (stats)
		stats->nr_override++;

	/* Forgive service debt by making the placed task immediately eligible. */
	return 0;
}

SEC(".struct_ops")
struct sched_ext_ops scx_fair_vlag_ops = {
	.fair_select_vlag = (void *)scx_fair_vlag_select_vlag,
	.flags = SCX_OPS_FAIR,
	.name = "scx_fair_vlag",
};
