// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */

#include <scx/fair.bpf.h>

char _license[] SEC("license") = "GPL";

SEC("struct_ops/fair_select_cpu")
s32 BPF_PROG(invalid_mixed_fair_select_cpu, struct task_struct *p,
	     s32 prev_cpu, u64 wake_flags)
{
	return -1;
}

SEC("struct_ops/enqueue")
void BPF_PROG(invalid_mixed_enqueue, struct task_struct *p, u64 enq_flags)
{
}

SEC(".struct_ops")
struct sched_ext_ops invalid_mixed_ops = {
	.enqueue = (void *)invalid_mixed_enqueue,
	.fair_select_cpu = (void *)invalid_mixed_fair_select_cpu,
	.flags = SCX_OPS_FAIR,
	.name = "invalid_mixed",
};

SEC("struct_ops/fair_select_cpu")
s32 BPF_PROG(invalid_regular_fair_select_cpu, struct task_struct *p,
	     s32 prev_cpu, u64 wake_flags)
{
	return -1;
}

SEC(".struct_ops")
struct sched_ext_ops invalid_regular_ops = {
	.fair_select_cpu = (void *)invalid_regular_fair_select_cpu,
	.name = "invalid_regular",
};

SEC(".struct_ops")
struct sched_ext_ops invalid_empty_fair_ops = {
	.flags = SCX_OPS_FAIR,
	.name = "invalid_empty",
};
