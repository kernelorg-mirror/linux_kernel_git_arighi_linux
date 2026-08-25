/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */
#ifndef __FAIR_EXT_COMMON_BPF_H
#define __FAIR_EXT_COMMON_BPF_H

/* Suppress kfunc prototypes generated without BPF address-space attributes. */
#define BPF_NO_KFUNC_PROTOTYPES

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <asm-generic/errno.h>

struct bpf_cpumask *bpf_cpumask_create(void) __ksym;
void bpf_cpumask_release(struct bpf_cpumask *cpumask) __ksym;
void bpf_cpumask_set_cpu(u32 cpu, struct bpf_cpumask *cpumask) __ksym;
void bpf_cpumask_clear_cpu(u32 cpu, struct bpf_cpumask *cpumask) __ksym;
bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask) __ksym;
bool bpf_cpumask_test_and_clear_cpu(u32 cpu, struct bpf_cpumask *cpumask) __ksym;
u32 bpf_cpumask_any_and_distribute(const struct cpumask *src1,
				   const struct cpumask *src2) __ksym;
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

s32 sched_fair_bpf_select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags,
			      const struct cpumask *preferred_mask__nullable) __ksym;
s32 sched_fair_bpf_cpu_idle(s32 cpu) __ksym;
s32 sched_fair_bpf_has_idle_cpu(const struct cpumask *preferred_mask) __ksym;

#endif /* __FAIR_EXT_COMMON_BPF_H */
