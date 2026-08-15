// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */

#include <scx/fair.bpf.h>

char _license[] SEC("license") = "GPL";

#define private(name) SEC(".bss." #name) __attribute__((aligned(8)))
#define FAIR_EXT_VLAG_PLACE 0x04
#define FAIR_EXT_VLAG_RENEW 0x01

private(MASK) static struct bpf_cpumask __kptr *preferred_mask;

int target_pid = -1;
int target_cpu = -1;
int preferred_cpu = -1;
bool use_fair_mask;
bool use_vlag;
bool invalid_vlag;
u64 nr_calls;
u64 nr_overrides;
u64 nr_fallbacks;
u64 nr_fair_mask;
u64 nr_fair_mask_empty;
u64 nr_cpu_idle;
u64 nr_vlag_calls;
u64 nr_vlag_place;
u64 nr_vlag_renew;
u64 nr_vlag_select;
u64 nr_vlag_invalid;
u64 nr_balance;
u64 nr_idle_queries;

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

SEC("struct_ops/fair_select_cpu")
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
			cpu = scx_fair_bpf_select_cpu(p, prev_cpu, wake_flags,
						      mask);
		if (cpu == -EINVAL)
			__sync_fetch_and_add(&nr_fair_mask_empty, 1);
		if (cpu >= 0) {
			idle = scx_fair_bpf_cpu_idle(cpu);
			if (idle >= 0)
				__sync_fetch_and_add(&nr_cpu_idle, 1);
			if (idle == 0)
				cpu = scx_fair_bpf_select_cpu(p, prev_cpu,
							      wake_flags, NULL);
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

SEC("struct_ops/fair_select_vlag")
s64 BPF_PROG(select_vlag, struct task_struct *p,
	     const struct fair_ext_vlag_ctx *state)
{
	if (target_pid >= 0 && p->pid != target_pid)
		return state->vlag;

	__sync_fetch_and_add(&nr_vlag_calls, 1);
	if (state->flags & FAIR_EXT_VLAG_PLACE)
		__sync_fetch_and_add(&nr_vlag_place, 1);
	if (state->flags & FAIR_EXT_VLAG_RENEW)
		__sync_fetch_and_add(&nr_vlag_renew, 1);

	if (invalid_vlag) {
		__sync_fetch_and_add(&nr_vlag_invalid, 1);
		return state->vlag_min - 1;
	}
	if (use_vlag) {
		__sync_fetch_and_add(&nr_vlag_select, 1);
		return 0;
	}

	return state->vlag;
}

SEC("struct_ops/fair_balance")
s32 BPF_PROG(balance, const struct fair_ext_balance_ctx *balance_state)
{
	const struct cpumask *mask;

	__sync_fetch_and_add(&nr_balance, 1);
	mask = (const struct cpumask *)preferred_mask;
	if (mask && scx_fair_bpf_has_idle_cpu(mask) >= 0)
		__sync_fetch_and_add(&nr_idle_queries, 1);
	return FAIR_EXT_BALANCE_CONTINUE;
}

SEC(".struct_ops")
struct sched_ext_ops ext_ops = {
	.fair_select_cpu = (void *)select_cpu,
	.fair_select_vlag = (void *)select_vlag,
	.fair_balance = (void *)balance,
	.flags = SCX_OPS_FAIR,
	.name = "fair_ext_test",
};
