// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */

#include <fair_ext/fair.bpf.h>

char _license[] SEC("license") = "GPL";

SEC("struct_ops/can_migrate_task")
s32 BPF_PROG(can_migrate_task, struct task_struct *p, s32 src_cpu, s32 dst_cpu)
{
	return FAIR_EXT_CAN_MIGRATE_CONTINUE;
}

SEC(".struct_ops")
struct sched_fair_ops valid_migrate_ops = {
	.can_migrate_task = (void *)can_migrate_task,
	.name = "valid_migrate",
};

SEC(".struct_ops")
struct sched_fair_ops invalid_empty_ops = {
	.name = "invalid_empty",
};
