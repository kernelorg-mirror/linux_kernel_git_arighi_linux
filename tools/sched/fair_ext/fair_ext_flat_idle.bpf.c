// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 *
 * Flat idle CPU tracking implemented entirely with a BPF cpumask.
 */
#include <fair_ext/fair.bpf.h>

char _license[] SEC("license") = "GPL";

#define MAX_CLAIM_RETRIES 4

static struct bpf_cpumask __kptr *idle_mask SEC(".bss.IDLE_MASK");

const volatile u32 nr_cpu_ids = 1;

u64 nr_idle_enter;
u64 nr_idle_exit;
u64 nr_select;
u64 nr_claimed;
u64 nr_fallback;

SEC("syscall")
int init_idle_mask(void *ctx)
{
	struct bpf_cpumask *mask, *old;

	mask = bpf_cpumask_create();
	if (!mask)
		return -ENOMEM;

	old = bpf_kptr_xchg(&idle_mask, mask);
	if (old)
		bpf_cpumask_release(old);

	return 0;
}

SEC("struct_ops/update_idle")
void BPF_PROG(fair_ext_flat_idle_update_idle, s32 cpu, bool idle)
{
	struct bpf_cpumask *mask;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return;

	mask = idle_mask;
	if (!mask)
		return;

	if (idle) {
		bpf_cpumask_set_cpu(cpu, mask);
		__sync_fetch_and_add(&nr_idle_enter, 1);
	} else {
		bpf_cpumask_clear_cpu(cpu, mask);
		__sync_fetch_and_add(&nr_idle_exit, 1);
	}
}

static s32 pick_idle_cpu(struct bpf_cpumask *mask, const struct cpumask *cpus_allowed)
{
	s32 cpu = -1;
	int i;

#pragma unroll
	for (i = 0; i < MAX_CLAIM_RETRIES; i++) {
		cpu = bpf_cpumask_any_and_distribute((const struct cpumask *)mask,
						     cpus_allowed);
		if (cpu < 0 || cpu >= nr_cpu_ids)
			return -1;

		if (bpf_cpumask_test_and_clear_cpu(cpu, mask))
			return cpu;
	}

	return -1;
}

SEC("struct_ops/select_cpu")
s32 BPF_PROG(fair_ext_flat_idle_select_cpu, struct task_struct *p, s32 prev_cpu,
	     u64 wake_flags)
{
	struct bpf_cpumask *mask;
	s32 cpu = -1;

	__sync_fetch_and_add(&nr_select, 1);
	mask = idle_mask;
	if (!mask)
		return -1;

	if (bpf_cpumask_test_and_clear_cpu(prev_cpu, mask)) {
		__sync_fetch_and_add(&nr_claimed, 1);
		return prev_cpu;
	}

	cpu = pick_idle_cpu(mask, p->cpus_ptr);
	if (cpu < 0) {
		__sync_fetch_and_add(&nr_fallback, 1);
		return -1;
	}
	__sync_fetch_and_add(&nr_claimed, 1);

	return cpu;
}

SEC(".struct_ops")
struct sched_fair_ops fair_ext_flat_idle_ops = {
	.select_cpu = (void *)fair_ext_flat_idle_select_cpu,
	.update_idle = (void *)fair_ext_flat_idle_update_idle,
	.name = "fair_ext_flat_idle",
};
