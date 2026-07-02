// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 *
 * Verify that SCX_OPS_ENQ_BLOCKED passes blocked proxy donors through
 * ops.enqueue().
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

s32 donor_pid;
u64 nr_blocked_enqueues;

UEI_DEFINE(uei);

void BPF_STRUCT_OPS(enq_blocked_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (scx_bpf_task_is_blocked(p)) {
		if (p->pid == donor_pid)
			__sync_fetch_and_add(&nr_blocked_enqueues, 1);

		scx_bpf_dsq_insert(p,
				   SCX_DSQ_LOCAL_ON | scx_bpf_task_cpu(p),
				   SCX_SLICE_DFL, enq_flags);
		return;
	}

	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(enq_blocked_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops enq_blocked_ops = {
	.enqueue		= (void *)enq_blocked_enqueue,
	.exit			= (void *)enq_blocked_exit,
	.name			= "enq_blocked",
};
