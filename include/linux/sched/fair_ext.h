/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_FAIR_EXT_H
#define _LINUX_SCHED_FAIR_EXT_H

#include <linux/types.h>

enum fair_ext_balance_flags {
	FAIR_EXT_BALANCE_IDLE		= 1U << 0,
	FAIR_EXT_BALANCE_NEWLY_IDLE	= 1U << 1,
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
 * @nr_running: number of runnable fair tasks on @cpu
 * @flags: %FAIR_EXT_BALANCE_* flags describing the balance pass
 */
struct fair_ext_balance_ctx {
	s32 cpu;
	u32 nr_running;
	u64 flags;
};

#endif /* _LINUX_SCHED_FAIR_EXT_H */
