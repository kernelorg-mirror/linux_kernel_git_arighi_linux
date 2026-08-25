// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 *
 * A no-op fair_ext policy for measuring callback overhead.
 */
#include <fair_ext/fair.bpf.h>

char _license[] SEC("license") = "GPL";

SEC("struct_ops/select_cpu")
s32 BPF_PROG(fair_ext_noop_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	return -1;
}

SEC("struct_ops/balance")
s32 BPF_PROG(fair_ext_noop_balance, const struct fair_ext_balance_ctx *balance_state)
{
	return FAIR_EXT_BALANCE_CONTINUE;
}

SEC("struct_ops/can_migrate_task")
s32 BPF_PROG(fair_ext_noop_can_migrate_task, struct task_struct *p, s32 src_cpu,
	     s32 dst_cpu)
{
	return FAIR_EXT_CAN_MIGRATE_CONTINUE;
}

SEC(".struct_ops")
struct sched_fair_ops fair_ext_noop_ops = {
	.select_cpu = (void *)fair_ext_noop_select_cpu,
	.balance = (void *)fair_ext_noop_balance,
	.can_migrate_task = (void *)fair_ext_noop_can_migrate_task,
	.name = "fair_ext_noop",
};
