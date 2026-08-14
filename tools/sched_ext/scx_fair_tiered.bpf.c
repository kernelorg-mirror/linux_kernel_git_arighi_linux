// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 *
 * A tiered fair_ext CPU-placement policy.
 *
 * CPU placement optionally runs fair within a userspace-provided CPU mask and
 * falls back to unrestricted fair placement when the preferred result is busy.
 * Load balancing into non-preferred CPUs is deferred while a preferred CPU is
 * idle, but otherwise remains under fair's control.
 */
#include <scx/fair.bpf.h>

char _license[] SEC("license") = "GPL";

static struct bpf_cpumask __kptr *preferred_mask SEC(".bss.CPU_MASK");

struct scx_fair_tiered_stats {
	u64 nr_select;
	u64 nr_select_preferred;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct scx_fair_tiered_stats));
	__uint(max_entries, 1);
} stats SEC(".maps");

static __always_inline struct scx_fair_tiered_stats *get_stats(void)
{
	u32 idx = 0;

	return bpf_map_lookup_elem(&stats, &idx);
}

SEC("syscall")
int init_preferred_mask(void *ctx)
{
	struct bpf_cpumask *mask, *old;

	mask = bpf_cpumask_create();
	if (!mask)
		return -ENOMEM;

	old = bpf_kptr_xchg(&preferred_mask, mask);
	if (old)
		bpf_cpumask_release(old);

	return 0;
}

SEC("syscall")
int add_preferred_cpu(s32 *preferred_cpu)
{
	struct bpf_cpumask *mask;
	int ret = 0;

	bpf_rcu_read_lock();
	mask = preferred_mask;
	if (mask)
		bpf_cpumask_set_cpu(*preferred_cpu, mask);
	else
		ret = -ENOENT;
	bpf_rcu_read_unlock();

	return ret;
}

SEC("struct_ops/fair_select_cpu")
s32 BPF_PROG(scx_fair_tiered_select_cpu, struct task_struct *p, s32 prev_cpu,
	     u64 wake_flags)
{
	const struct cpumask *mask;
	struct scx_fair_tiered_stats *stats;
	s32 cpu;

	stats = get_stats();
	if (stats)
		stats->nr_select++;

	/*
	 * Implement preferred CPUs as a soft preference: first let fair select
	 * a CPU from the preferred mask and keep that choice if the CPU is
	 * idle; if the selected preferred CPU is busy (or its idle state cannot
	 * be queried), retry without a mask so fair can use the task's full
	 * effective affinity. The loader only attaches this callback after the
	 * preferred mask has been initialized; fail back to native placement if
	 * it is unexpectedly unavailable.
	 */
	mask = (const struct cpumask *)preferred_mask;
	if (!mask)
		return -1;

	cpu = scx_fair_bpf_select_cpu(p, prev_cpu, wake_flags, mask);
	if (cpu < 0 || !scx_fair_bpf_cpu_idle(cpu))
		return -1;

	if (stats)
		stats->nr_select_preferred++;

	return cpu;
}

SEC("struct_ops/fair_balance")
s32 BPF_PROG(scx_fair_tiered_balance,
	     const struct fair_ext_balance_ctx *balance_state)
{
	const struct cpumask *mask;
	bool preferred = false;
	s32 has_idle = 0;
	s32 cpu = balance_state->cpu;

	/*
	 * Fair balancing is pull-based. Always allow a preferred CPU to balance
	 * so that, when idle, it can pull work back from the fallback CPUs.
	 * Suppress only a non-preferred CPU's pass while the preferred set
	 * still has idle capacity, preventing that CPU from pulling more work.
	 * Once all preferred CPUs are busy, allow native balancing everywhere.
	 * A missing mask or an idle-query error also fails open to native balancing.
	 */
	mask = (const struct cpumask *)preferred_mask;
	if (!mask)
		return FAIR_EXT_BALANCE_CONTINUE;

	preferred = bpf_cpumask_test_cpu(cpu, mask);
	if (!preferred)
		has_idle = scx_fair_bpf_has_idle_cpu(mask);

	if (preferred || has_idle <= 0)
		return FAIR_EXT_BALANCE_CONTINUE;

	return FAIR_EXT_BALANCE_HANDLED;
}

SEC(".struct_ops")
struct sched_ext_ops scx_fair_tiered_ops = {
	.fair_select_cpu = (void *)scx_fair_tiered_select_cpu,
	.fair_balance = (void *)scx_fair_tiered_balance,
	.flags = SCX_OPS_FAIR,
	.name = "scx_fair_tiered",
};
