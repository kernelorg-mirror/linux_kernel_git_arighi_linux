/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_FAIR_EXT_H
#define _LINUX_SCHED_FAIR_EXT_H

#include <linux/types.h>

#define FAIR_EXT_OPS_NAME_LEN	128

struct task_struct;

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
	 * @name: Name of the fair extension
	 *
	 * Must be a non-empty valid BPF object name.
	 */
	char name[FAIR_EXT_OPS_NAME_LEN];
};

#endif /* _LINUX_SCHED_FAIR_EXT_H */
