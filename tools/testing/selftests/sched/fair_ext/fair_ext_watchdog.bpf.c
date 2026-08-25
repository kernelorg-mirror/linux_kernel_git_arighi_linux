// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */

#include <fair_ext/fair.bpf.h>

char _license[] SEC("license") = "GPL";

u64 nr_calls;

SEC("struct_ops/select_cpu")
s32 BPF_PROG(select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	__sync_fetch_and_add(&nr_calls, 1);
	return -1;
}

SEC(".struct_ops")
struct sched_fair_ops ext_ops = {
	.select_cpu = (void *)select_cpu,
	.name = "fair_ext_watchdog",
};
