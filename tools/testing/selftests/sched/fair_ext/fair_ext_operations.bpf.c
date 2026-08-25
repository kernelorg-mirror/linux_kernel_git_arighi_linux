// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */

#include <fair_ext/fair.bpf.h>

char _license[] SEC("license") = "GPL";

static struct bpf_cpumask __kptr *preferred_mask SEC(".bss.MASK");

int target_pid = -1;
int target_cpu = -1;
int preferred_cpu = -1;
bool use_fair_mask;
u64 nr_calls;
u64 nr_overrides;
u64 nr_fallbacks;
u64 nr_fair_mask;
u64 nr_fair_mask_empty;
u64 nr_cpu_idle;
u64 nr_balance;
u64 nr_idle_queries;
u64 nr_update_idle;
u64 nr_idle_enter;
u64 nr_idle_exit;

SEC("syscall")
int init_preferred_mask(void *ctx)
{
	struct bpf_cpumask *mask, *old;

	mask = bpf_cpumask_create();
	if (!mask)
		return -1;

	bpf_cpumask_set_cpu(preferred_cpu, mask);
	old = bpf_kptr_xchg(&preferred_mask, mask);
	if (old)
		bpf_cpumask_release(old);

	return 0;
}

SEC("struct_ops/select_cpu")
s32 BPF_PROG(select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	if (target_pid >= 0 && p->pid != target_pid)
		return -1;

	__sync_fetch_and_add(&nr_calls, 1);
	if (use_fair_mask) {
		const struct cpumask *mask;
		s32 cpu = -1;
		s32 idle;

		mask = (const struct cpumask *)preferred_mask;
		if (mask)
			cpu = sched_fair_bpf_select_cpu(p, prev_cpu, wake_flags, mask);
		if (cpu == -EINVAL)
			__sync_fetch_and_add(&nr_fair_mask_empty, 1);
		if (cpu >= 0) {
			idle = sched_fair_bpf_cpu_idle(cpu);
			if (idle >= 0)
				__sync_fetch_and_add(&nr_cpu_idle, 1);
			if (idle == 0)
				cpu = sched_fair_bpf_select_cpu(p, prev_cpu, wake_flags, NULL);
		}
		__sync_fetch_and_add(&nr_fair_mask, 1);
		return cpu;
	}

	if (target_cpu < 0) {
		__sync_fetch_and_add(&nr_fallbacks, 1);
		return -1;
	}

	__sync_fetch_and_add(&nr_overrides, 1);
	return target_cpu;
}

SEC("struct_ops/balance")
s32 BPF_PROG(balance, const struct fair_ext_balance_ctx *balance_state)
{
	const struct cpumask *mask;

	__sync_fetch_and_add(&nr_balance, 1);
	mask = (const struct cpumask *)preferred_mask;
	if (mask && sched_fair_bpf_has_idle_cpu(mask) >= 0)
		__sync_fetch_and_add(&nr_idle_queries, 1);
	return FAIR_EXT_BALANCE_CONTINUE;
}

SEC("struct_ops/update_idle")
void BPF_PROG(update_idle, s32 cpu, bool idle)
{
	__sync_fetch_and_add(&nr_update_idle, 1);
	if (idle)
		__sync_fetch_and_add(&nr_idle_enter, 1);
	else
		__sync_fetch_and_add(&nr_idle_exit, 1);
}

SEC(".struct_ops")
struct sched_fair_ops ext_ops = {
	.select_cpu = (void *)select_cpu,
	.balance = (void *)balance,
	.update_idle = (void *)update_idle,
	.name = "fair_ext_test",
};
