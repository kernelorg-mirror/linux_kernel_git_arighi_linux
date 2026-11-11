/* SPDX-License-Identifier: GPL-2.0 */
/*
 * CPU topology for scx_pvsched.bpf.h, read from sysfs by the loaders: the LLC
 * of every CPU and its capacity, grouped in tiers, the fastest first.
 *
 * Copyright (c) 2026 NVIDIA Corporation.
 */
#ifndef __SCX_PV_TOPO_H
#define __SCX_PV_TOPO_H

#include <stdio.h>
#include <stdbool.h>
#include <linux/types.h>
#include "scx_pv.h"

struct pv_topo {
	__u32 nr_cpus;
	__u32 nr_llcs;
	__u32 nr_tiers;
	bool asym_capacity;
	bool smt;
	__u32 llc[PV_MAX_CPUS];
	__u32 cap[PV_MAX_CPUS];
	__u32 tier[PV_MAX_CPUS];
	/* CPUs grouped by LLC: those of LLC l from llc_cpus[llc_start[l]] */
	__u16 llc_cpus[PV_MAX_CPUS];
	__u32 llc_start[PV_MAX_LLCS + 1];
	/* Lowest-numbered thread of every CPU's core */
	__u16 smt_first[PV_MAX_CPUS];
};

static long pv_read_long(const char *fmt, int cpu, long dfl)
{
	char path[128];
	long val = dfl;
	FILE *f;

	snprintf(path, sizeof(path), fmt, cpu);
	f = fopen(path, "r");
	if (!f)
		return dfl;
	if (fscanf(f, "%ld", &val) != 1)
		val = dfl;
	fclose(f);
	return val;
}

/* CPUs without an L3 or with more LLCs than PV_MAX_LLCS share LLC 0 */
static void pv_read_topo(struct pv_topo *t, __u32 nr_cpus)
{
	long llc_first[PV_MAX_LLCS], caps[PV_MAX_TIERS];
	__u32 cpu, i, j, n;

	t->nr_cpus = nr_cpus;
	t->nr_llcs = 0;
	t->nr_tiers = 0;
	t->smt = false;
	for (cpu = 0; cpu < nr_cpus; cpu++) {
		/* The first CPU of the shared_cpu_list names the LLC */
		long first = pv_read_long("/sys/devices/system/cpu/cpu%d/cache/index3/shared_cpu_list",
					  cpu, -1);

		for (i = 0; i < t->nr_llcs && llc_first[i] != first; i++)
			;
		if (i == t->nr_llcs) {
			if (t->nr_llcs < PV_MAX_LLCS)
				llc_first[t->nr_llcs++] = first;
			else
				i = 0;
		}
		t->llc[cpu] = i;
		t->cap[cpu] = pv_read_long("/sys/devices/system/cpu/cpu%d/cpu_capacity", cpu, 1024);
		/* The sibling list starts with the core's first thread */
		t->smt_first[cpu] = pv_read_long("/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list",
						 cpu, cpu);
		if (t->smt_first[cpu] != cpu)
			t->smt = true;
	}

	n = 0;
	for (i = 0; i < t->nr_llcs; i++) {
		t->llc_start[i] = n;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			if (t->llc[cpu] == i)
				t->llc_cpus[n++] = cpu;
	}
	t->llc_start[t->nr_llcs] = n;

	/* Distinct capacities, the highest first */
	for (cpu = 0; cpu < nr_cpus; cpu++) {
		for (i = 0; i < t->nr_tiers && caps[i] != t->cap[cpu]; i++)
			;
		if (i < t->nr_tiers || t->nr_tiers == PV_MAX_TIERS)
			continue;
		for (i = t->nr_tiers; i > 0 && caps[i - 1] < t->cap[cpu]; i--)
			caps[i] = caps[i - 1];
		caps[i] = t->cap[cpu];
		t->nr_tiers++;
	}
	/* More capacities than tiers end up in the slowest tier */
	for (cpu = 0; cpu < nr_cpus; cpu++) {
		for (j = 0; j < t->nr_tiers - 1 && caps[j] > t->cap[cpu]; j++)
			;
		t->tier[cpu] = j;
	}
	t->asym_capacity = t->nr_tiers > 1;
}

/* Fill the topology variables of scx_pvsched.bpf.h in @skel's rodata */
#define PV_SET_TOPO(skel, nr) ({						\
	struct pv_topo __t;							\
	__u32 __cpu;								\
										\
	pv_read_topo(&__t, (nr));						\
	(skel)->rodata->nr_cpu_ids = __t.nr_cpus;				\
	(skel)->rodata->nr_llcs = __t.nr_llcs;					\
	(skel)->rodata->nr_tiers = __t.nr_tiers;				\
	(skel)->rodata->asym_capacity = __t.asym_capacity;			\
	(skel)->rodata->smt = __t.smt;						\
	for (__cpu = 0; __cpu < __t.nr_cpus; __cpu++) {				\
		(skel)->rodata->cpu_llc[__cpu] = __t.llc[__cpu];		\
		(skel)->rodata->cpu_cap[__cpu] = __t.cap[__cpu];		\
		(skel)->rodata->cpu_tier[__cpu] = __t.tier[__cpu];		\
		(skel)->rodata->llc_cpus[__cpu] = __t.llc_cpus[__cpu];		\
		(skel)->rodata->cpu_smt_first[__cpu] = __t.smt_first[__cpu];	\
	}									\
	for (__cpu = 0; __cpu <= __t.nr_llcs; __cpu++)				\
		(skel)->rodata->llc_start[__cpu] = __t.llc_start[__cpu];	\
	printf("%u CPUs, %u LLCs, %u capacity tiers\n", __t.nr_cpus,		\
	       __t.nr_llcs, __t.nr_tiers);					\
})

#endif /* __SCX_PV_TOPO_H */
