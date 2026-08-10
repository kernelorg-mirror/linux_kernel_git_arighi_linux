/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_FAIR_EXT_H
#define _LINUX_SCHED_FAIR_EXT_H

#include <linux/types.h>

enum fair_ext_vlag_flags {
	FAIR_EXT_VLAG_RENEW		= 1U << 0,
	FAIR_EXT_VLAG_YIELD		= 1U << 1,
	FAIR_EXT_VLAG_PLACE		= 1U << 2,
	FAIR_EXT_VLAG_INITIAL		= 1U << 3,
	FAIR_EXT_VLAG_WAKEUP		= 1U << 4,
	FAIR_EXT_VLAG_MIGRATED		= 1U << 5,
};

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
 * struct fair_ext_vlag_ctx - virtual lag proposed by fair
 * @vlag: virtual lag, average vruntime minus entity vruntime
 * @vlag_min: minimum virtual lag accepted by fair
 * @vlag_max: maximum virtual lag accepted by fair
 * @flags: %FAIR_EXT_VLAG_* flags describing the update
 */
struct fair_ext_vlag_ctx {
	s64 vlag;
	s64 vlag_min;
	s64 vlag_max;
	u64 flags;
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
