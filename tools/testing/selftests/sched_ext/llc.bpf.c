// SPDX-License-Identifier: GPL-2.0
/*
 * A scheduler that validates the behavior of the LLC-aware
 * functionalities.
 *
 * The scheduler creates a separate DSQ for each LLC node, ensuring tasks
 * are exclusively processed by CPUs within their respective nodes. Idle
 * CPUs are selected only within the same node, so task migration can only
 * occurs between CPUs belonging to the same LLC.
 *
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

static int cpu_to_llc(s32 cpu)
{
	const struct cpumask *llc_mask = scx_bpf_get_cpumask_llc(cpu);
	int llc_id;

	/*
	 * Use the first CPU in the sched_domain's span as a unique and
	 * stable identifier for the LLC domain.
	 *
	 * Each llc_mask spans a distinct group of CPUs that share the same
	 * LLC, and no two such domains overlap. This makes the first CPU
	 * in the span a natural and deterministic representative for the
	 * domain, avoiding the need for additional mapping.
	 */
	llc_id = bpf_cpumask_first(llc_mask);
	if (llc_id > scx_bpf_nr_cpu_ids())
		llc_id = -ENOENT;

	scx_bpf_put_cpumask_llc(llc_mask);

	return llc_id;
}

static void
validate_idle_cpu(const struct task_struct *p, const struct cpumask *allowed, s32 cpu)
{
	if (scx_bpf_test_and_clear_cpu_idle(cpu))
		scx_bpf_error("CPU %d should be marked as busy", cpu);

	if (!bpf_cpumask_test_cpu(cpu, allowed))
		scx_bpf_error("CPU %d not in the allowed domain for %d (%s)",
			      cpu, p->pid, p->comm);
}

s32 BPF_STRUCT_OPS(llc_select_cpu,
		   struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct cpumask *llc_mask = scx_bpf_get_cpumask_llc(prev_cpu);
	s32 cpu;

	/*
	 * Select an idle CPU within the LLC domain.
	 */
	cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, llc_mask, 0);
	if (cpu >= 0) {
		validate_idle_cpu(p, llc_mask, cpu);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		goto out_put_cpumask;
	}
	cpu = prev_cpu;

out_put_cpumask:
	scx_bpf_put_cpumask_llc(llc_mask);

	return cpu;
}

void BPF_STRUCT_OPS(llc_enqueue, struct task_struct *p, u64 enq_flags)
{
	int llc = cpu_to_llc(scx_bpf_task_cpu(p));

	scx_bpf_dsq_insert(p, llc, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(llc_dispatch, s32 cpu, struct task_struct *prev)
{
	int llc = cpu_to_llc(cpu);

	scx_bpf_dsq_move_to_local(llc);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(llc_init)
{
	int cpu;

	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
		int node = scx_bpf_cpu_node(cpu);
		int llc = cpu_to_llc(cpu);

		if (llc < 0)
			scx_bpf_error("CPU %d does not belong to any LLC", cpu);

		/*
		 * We may attempt to create the same per-LLC DSQ multiple
		 * times, for simplicity just ignore errors if the DSQ
		 * already exists.
		 */
		scx_bpf_create_dsq(llc, node);
	}

	return 0;
}

void BPF_STRUCT_OPS(llc_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops llc_ops = {
	.select_cpu		= (void *)llc_select_cpu,
	.enqueue		= (void *)llc_enqueue,
	.dispatch		= (void *)llc_dispatch,
	.init			= (void *)llc_init,
	.exit			= (void *)llc_exit,
	.name			= "llc",
};
