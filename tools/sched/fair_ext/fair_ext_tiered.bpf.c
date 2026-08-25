// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 *
 * A tiered fair_ext CPU-placement policy.
 *
 * CPU placement optionally runs fair within a userspace-provided CPU mask and
 * falls back to unrestricted fair placement when the preferred result is busy.
 *
 * The preference can be limited to a cgroup subtree. Load balancing into
 * non-preferred CPUs is deferred while a preferred CPU is idle, but otherwise
 * remains under fair's control.
 */
#include <fair_ext/fair.bpf.h>

char _license[] SEC("license") = "GPL";

struct cgroup *bpf_cgroup_from_id(u64 cgroup_id) __ksym;
void bpf_cgroup_release(struct cgroup *cgroup) __ksym;
long bpf_task_under_cgroup(struct task_struct *task, struct cgroup *ancestor) __ksym;

static struct bpf_cpumask __kptr *preferred_mask SEC(".bss.CPU_MASK");

struct target_cgroup_value {
	struct cgroup __kptr *cgroup;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct target_cgroup_value);
	__uint(max_entries, 1);
} target_cgroup SEC(".maps");

const volatile u64 target_cgroup_id;

struct fair_ext_tiered_stats {
	u64 nr_select;
	u64 nr_select_preferred;
	u64 nr_migrate;
	u64 nr_migrate_skipped;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct fair_ext_tiered_stats));
	__uint(max_entries, 1);
} stats SEC(".maps");

static struct fair_ext_tiered_stats *get_stats(void)
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

SEC("syscall")
int init_target_cgroup(u64 *cgroup_id)
{
	struct target_cgroup_value *value;
	struct cgroup *cgroup, *old;
	u32 idx = 0;

	value = bpf_map_lookup_elem(&target_cgroup, &idx);
	if (!value)
		return -ENOENT;

	cgroup = bpf_cgroup_from_id(*cgroup_id);
	if (!cgroup)
		return -ENOENT;

	old = bpf_kptr_xchg(&value->cgroup, cgroup);
	if (old)
		bpf_cgroup_release(old);

	return 0;
}

static bool task_in_target_cgroup(struct task_struct *p)
{
	struct target_cgroup_value *value;
	struct cgroup *cgroup;
	u32 idx = 0;

	value = bpf_map_lookup_elem(&target_cgroup, &idx);
	if (!value)
		return false;

	cgroup = value->cgroup;
	if (!cgroup)
		return false;

	return bpf_task_under_cgroup(p, cgroup);
}

SEC("struct_ops/select_cpu")
s32 BPF_PROG(fair_ext_tiered_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct cpumask *mask;
	struct fair_ext_tiered_stats *stats;
	s32 cpu;

	stats = get_stats();
	if (stats)
		stats->nr_select++;

	if (target_cgroup_id && !task_in_target_cgroup(p))
		return -1;

	/*
	 * Implement preferred CPUs as a soft preference: first let fair select
	 * a CPU from the preferred mask and keep that choice if the CPU is
	 * idle; if the selected preferred CPU is busy (or its idle state cannot
	 * be queried), retry without a mask so fair can use the task's full
	 * effective affinity.
	 */
	mask = (const struct cpumask *)preferred_mask;
	if (!mask)
		return -1;

	cpu = sched_fair_bpf_select_cpu(p, prev_cpu, wake_flags, mask);
	if (cpu < 0 || !sched_fair_bpf_cpu_idle(cpu))
		return -1;

	if (stats)
		stats->nr_select_preferred++;

	return cpu;
}

SEC("struct_ops/balance")
s32 BPF_PROG(fair_ext_tiered_balance, const struct fair_ext_balance_ctx *balance_state)
{
	const struct cpumask *mask;
	bool preferred = false;
	s32 has_idle = 0;
	s32 cpu = balance_state->cpu;

	/*
	 * Give preferred CPUs priority when pulling work. A preferred CPU is
	 * always allowed to balance so it can pull work from fallback CPUs when
	 * it becomes idle. A fallback CPU is allowed to balance only when no
	 * preferred CPU is idle; otherwise, let the preferred CPUs pull the
	 * available work first.
	 *
	 * If there's no idle CPU in the preferred mask, fall back to native
	 * balancing.
	 */
	mask = (const struct cpumask *)preferred_mask;
	if (!mask)
		return FAIR_EXT_BALANCE_CONTINUE;

	preferred = bpf_cpumask_test_cpu(cpu, mask);
	if (!preferred)
		has_idle = sched_fair_bpf_has_idle_cpu(mask);

	if (preferred || has_idle <= 0)
		return FAIR_EXT_BALANCE_CONTINUE;

	return FAIR_EXT_BALANCE_HANDLED;
}

SEC("struct_ops/can_migrate_task")
s32 BPF_PROG(fair_ext_tiered_can_migrate_task, struct task_struct *p, s32 src_cpu,
	     s32 dst_cpu)
{
	const struct cpumask *mask;
	struct fair_ext_tiered_stats *stats;
	s32 has_idle;

	if (!task_in_target_cgroup(p))
		return FAIR_EXT_CAN_MIGRATE_CONTINUE;

	stats = get_stats();
	if (stats)
		stats->nr_migrate++;

	mask = (const struct cpumask *)preferred_mask;
	if (!mask || bpf_cpumask_test_cpu(dst_cpu, mask))
		return FAIR_EXT_CAN_MIGRATE_CONTINUE;

	has_idle = sched_fair_bpf_has_idle_cpu(mask);
	if (has_idle <= 0)
		return FAIR_EXT_CAN_MIGRATE_CONTINUE;

	if (stats)
		stats->nr_migrate_skipped++;
	return FAIR_EXT_CAN_MIGRATE_SKIP;
}

SEC(".struct_ops")
struct sched_fair_ops fair_ext_tiered_ops = {
	.select_cpu = (void *)fair_ext_tiered_select_cpu,
	.balance = (void *)fair_ext_tiered_balance,
	.can_migrate_task = (void *)fair_ext_tiered_can_migrate_task,
	.name = "fair_ext_tiered",
};
