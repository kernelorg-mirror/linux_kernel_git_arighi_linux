/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_FAIR_EXT_H
#define _LINUX_SCHED_FAIR_EXT_H

#include <linux/types.h>

#define FAIR_EXT_OPS_NAME_LEN	128

struct task_struct;

/**
 * enum fair_ext_idle_type - CPU idle state for a fair balance pass
 * @FAIR_EXT_CPU_NOT_IDLE: CPU is not idle
 * @FAIR_EXT_CPU_IDLE: CPU is idle
 * @FAIR_EXT_CPU_NEWLY_IDLE: CPU is newly idle
 */
enum fair_ext_idle_type {
	FAIR_EXT_CPU_NOT_IDLE,
	FAIR_EXT_CPU_IDLE,
	FAIR_EXT_CPU_NEWLY_IDLE,
};

/**
 * enum fair_ext_balance_ret - fair_ext balance callback result
 * @FAIR_EXT_BALANCE_CONTINUE: Continue native fair balancing
 * @FAIR_EXT_BALANCE_HANDLED: Suppress native fair balancing for this pass
 */
enum fair_ext_balance_ret {
	FAIR_EXT_BALANCE_CONTINUE	= 0,
	FAIR_EXT_BALANCE_HANDLED	= 1,
};

/**
 * struct fair_ext_balance_ctx - minimal fair balancing state
 * @cpu: CPU on whose behalf balancing is running
 * @idle: idle state of @cpu
 */
struct fair_ext_balance_ctx {
	s32 cpu;
	enum fair_ext_idle_type idle;
};

/**
 * struct sched_fair_ops - Operation table for BPF fair extensions
 *
 * Fair extensions override selected policy decisions while tasks remain in
 * fair_sched_class and the native fair scheduler retains runqueue ownership.
 */
struct sched_fair_ops {
	/**
	 * @select_cpu: Pick the target CPU for a fair-class task
	 * @p: task being placed
	 * @prev_cpu: CPU @p was most recently associated with
	 * @wake_flags: %FAIR_EXT_WAKE_* flags
	 *
	 * Return a negative value to use native fair CPU selection.
	 */
	s32 (*select_cpu)(struct task_struct *p, s32 prev_cpu, u64 wake_flags);

	/**
	 * @balance: Run a custom fair load-balancing pass
	 * @ctx: minimal state for the CPU requesting balance
	 */
	s32 (*balance)(const struct fair_ext_balance_ctx *ctx);

	/**
	 * @name: Name of the fair extension
	 *
	 * Must be a non-empty valid BPF object name.
	 */
	char name[FAIR_EXT_OPS_NAME_LEN];
};

#endif /* _LINUX_SCHED_FAIR_EXT_H */
