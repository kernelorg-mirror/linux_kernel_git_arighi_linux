// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 *
 * A no-op fair_ext policy for measuring callback overhead.
 */
#include <scx/fair.bpf.h>

char _license[] SEC("license") = "GPL";

SEC("struct_ops/fair_select_cpu")
s32 BPF_PROG(scx_fair_noop_select_cpu, struct task_struct *p, s32 prev_cpu,
	     u64 wake_flags)
{
	return -1;
}

SEC("struct_ops/fair_select_vlag")
s64 BPF_PROG(scx_fair_noop_select_vlag, struct task_struct *p,
	     const struct fair_ext_vlag_ctx *state)
{
	return state->vlag;
}

SEC("struct_ops/fair_balance")
s32 BPF_PROG(scx_fair_noop_balance,
	     const struct fair_ext_balance_ctx *balance_state)
{
	return FAIR_EXT_BALANCE_CONTINUE;
}

SEC(".struct_ops")
struct sched_ext_ops scx_fair_noop_ops = {
	.fair_select_cpu = (void *)scx_fair_noop_select_cpu,
	.fair_select_vlag = (void *)scx_fair_noop_select_vlag,
	.fair_balance = (void *)scx_fair_noop_balance,
	.flags = SCX_OPS_FAIR,
	.name = "scx_fair_noop",
};
