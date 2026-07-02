// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 *
 * Kernel mutex fixture for the sched_ext SCX_OPS_ENQ_BLOCKED selftest.
 */

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>

#include "../enq_blocked.h"

#define DONOR_WAIT_TIMEOUT	msecs_to_jiffies(2000)
#define DONOR_HOLD_TIME		msecs_to_jiffies(1000)

static DEFINE_MUTEX(test_mutex);
static atomic_t owner_ready = ATOMIC_INIT(0);
static atomic_t donor_started = ATOMIC_INIT(0);

static long run_owner(void)
{
	unsigned long timeout;
	long ret = 0;

	atomic_set(&donor_started, 0);
	mutex_lock(&test_mutex);
	atomic_set(&owner_ready, 1);

	timeout = jiffies + DONOR_WAIT_TIMEOUT;
	while (!atomic_read(&donor_started)) {
		if (time_after(jiffies, timeout)) {
			ret = -ETIMEDOUT;
			goto out;
		}
		cond_resched();
	}

	/* Keep yielding while the donor blocks on test_mutex. */
	timeout = jiffies + DONOR_HOLD_TIME;
	while (time_before(jiffies, timeout))
		cond_resched();

out:
	atomic_set(&owner_ready, 0);
	mutex_unlock(&test_mutex);
	return ret;
}

static long run_donor(void)
{
	if (!atomic_read(&owner_ready))
		return -EAGAIN;

	atomic_set(&donor_started, 1);
	mutex_lock(&test_mutex);
	mutex_unlock(&test_mutex);
	return 0;
}

static long enq_blocked_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	switch (cmd) {
	case ENQ_BLOCKED_IOCTL_OWNER:
		return run_owner();
	case ENQ_BLOCKED_IOCTL_DONOR:
		return run_donor();
	default:
		return -EINVAL;
	}
}

static const struct file_operations enq_blocked_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= enq_blocked_ioctl,
};

static struct miscdevice enq_blocked_device = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "scx_enq_blocked",
	.fops	= &enq_blocked_fops,
	.mode	= 0600,
};

module_misc_device(enq_blocked_device);
MODULE_AUTHOR("Andrea Righi <arighi@nvidia.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("sched_ext blocked donor test fixture");
