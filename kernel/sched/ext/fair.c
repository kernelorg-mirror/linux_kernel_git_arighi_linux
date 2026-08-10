// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 *
 * BPF programmable extensions to the fair scheduling class.
 */

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cpumask.h>
#include <linux/kobject.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/sched/fair_ext.h>
#include <linux/sched/signal.h>
#include <linux/static_call.h>

#include "../sched.h"
#include "fair.h"
#include "internal.h"

enum fair_ext_wake_flags {
	/* expose select WF_* flags as enums */
	FAIR_EXT_WAKE_EXEC		= WF_EXEC,
	FAIR_EXT_WAKE_FORK		= WF_FORK,
	FAIR_EXT_WAKE_TTWU		= WF_TTWU,
	FAIR_EXT_WAKE_SYNC		= WF_SYNC,
	FAIR_EXT_WAKE_CURRENT_CPU	= WF_CURRENT_CPU,
};

static DEFINE_MUTEX(fair_ext_mutex);
static struct sched_ext_ops __rcu *fair_ext_ops;
static struct sched_ext_ops *fair_ext_registered_ops;
static struct task_struct *fair_ext_watchdog_task;
static unsigned long fair_ext_watchdog_timeout;
static atomic_long_t fair_ext_watchdog_seq = ATOMIC_LONG_INIT(0);
static struct kobject *fair_ext_kobj;

#define FAIR_EXT_WATCHDOG_MAX_TIMEOUT	(30 * HZ)

struct fair_ext_select_ctx {
	struct task_struct *p;
};

struct fair_ext_balance_call_ctx {
	bool active;
};

static DEFINE_PER_CPU(struct fair_ext_select_ctx, fair_ext_select_ctx);
static DEFINE_PER_CPU(struct fair_ext_balance_call_ctx, fair_ext_balance_call_ctx);
static DEFINE_PER_CPU(cpumask_var_t, fair_ext_preferred_mask);

DEFINE_STATIC_CALL(fair_ext_select_cpu_call,
		   sched_ext_ops__fair_select_cpu);
DEFINE_STATIC_CALL(fair_ext_select_vlag_call,
		   sched_ext_ops__fair_select_vlag);
DEFINE_STATIC_CALL(fair_ext_balance_call, sched_ext_ops__fair_balance);

/* Keep each fair extension hook patched out until it is registered. */
DEFINE_STATIC_KEY_FALSE(__fair_ext_select_cpu_enabled);
DEFINE_STATIC_KEY_FALSE(__fair_ext_select_vlag_enabled);
DEFINE_STATIC_KEY_FALSE(__fair_ext_balance_enabled);

static void fair_ext_disable_callbacks(struct sched_ext_ops *ops);

static ssize_t state_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	const char *state;

	guard(mutex)(&fair_ext_mutex);
	if (!fair_ext_registered_ops)
		state = "disabled";
	else if (rcu_access_pointer(fair_ext_ops))
		state = "enabled";
	else
		state = "faulted";

	return sysfs_emit(buf, "%s\n", state);
}

static struct kobj_attribute state_attr = __ATTR_RO(state);

static ssize_t map_id_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	u32 id = 0;

	guard(mutex)(&fair_ext_mutex);
	if (fair_ext_registered_ops)
		id = bpf_struct_ops_id(fair_ext_registered_ops);

	return sysfs_emit(buf, "%u\n", id);
}

static struct kobj_attribute map_id_attr = __ATTR_RO(map_id);

static struct attribute *fair_ext_attrs[] = {
	&state_attr.attr,
	&map_id_attr.attr,
	NULL,
};

static const struct attribute_group fair_ext_attr_group = {
	.attrs = fair_ext_attrs,
};

int fair_ext_select_cpu(struct task_struct *p, int prev_cpu, int wake_flags)
{
	struct fair_ext_select_ctx *ctx;
	int cpu = -1;

	lockdep_assert_held(&p->pi_lock);
	lockdep_assert_preemption_disabled();

	guard(rcu)();
	ctx = this_cpu_ptr(&fair_ext_select_ctx);
	if (WARN_ON_ONCE(ctx->p))
		return cpu;

	ctx->p = p;
	cpu = static_call(fair_ext_select_cpu_call)(p, prev_cpu, wake_flags);
	ctx->p = NULL;

	return cpu;
}

bool fair_ext_select_vlag(struct cfs_rq *cfs_rq, struct sched_entity *se,
			  u64 flags, s64 *vlag)
{
	struct fair_ext_vlag_ctx state = {
		.vlag		= *vlag,
		.flags		= flags,
	};
	struct task_struct *p;
	s64 new_vlag;

	if (!entity_is_task(se))
		return false;

	p = task_of(se);
	lockdep_assert_rq_held(task_rq(p));
	lockdep_assert_preemption_disabled();
	fair_ext_init_vlag_bounds(cfs_rq, se, &state);

	guard(rcu)();
	new_vlag = static_call(fair_ext_select_vlag_call)(p, &state);
	if (new_vlag < state.vlag_min || new_vlag > state.vlag_max)
		return false;

	*vlag = new_vlag;
	return true;
}

bool fair_ext_balance(int cpu, u32 nr_running, u64 flags)
{
	struct fair_ext_balance_ctx state = {
		.cpu = cpu,
		.nr_running = nr_running,
		.flags = flags,
	};
	struct fair_ext_balance_call_ctx *ctx;
	bool handled = false;

	lockdep_assert_preemption_disabled();

	guard(rcu)();
	ctx = this_cpu_ptr(&fair_ext_balance_call_ctx);
	if (WARN_ON_ONCE(ctx->active))
		return handled;

	ctx->active = true;
	handled = static_call(fair_ext_balance_call)(&state) ==
		  FAIR_EXT_BALANCE_HANDLED;
	ctx->active = false;

	return handled;
}

static __always_inline void
fair_ext_watchdog_reset(struct task_struct *p, unsigned long now,
			unsigned long seq)
{
	p->scx.fair_ext_watchdog.runtime = p->se.sum_exec_runtime;
	p->scx.fair_ext_watchdog.at = now;
	p->scx.fair_ext_watchdog.seq = seq;
}

static __always_inline bool
fair_ext_watchdog_stalled(struct task_struct *p, unsigned long now,
			  unsigned long timeout, unsigned long seq)
{
	struct fair_ext_watchdog *watchdog = &p->scx.fair_ext_watchdog;
	u64 runtime = p->se.sum_exec_runtime;

	/*
	 * Only consecutive observations establish continuous runnable time.  A
	 * migration can move a task behind the runqueue scan cursor and make us
	 * miss it for one pass. Resetting the observation window in that case
	 * deliberately favors delayed detection over a false-positive timeout.
	 */
	if ((watchdog->seq != seq - 1 && watchdog->seq != seq) ||
	    watchdog->runtime != runtime) {
		fair_ext_watchdog_reset(p, now, seq);
		return false;
	}

	watchdog->seq = seq;
	return time_after(now, watchdog->at + timeout);
}

struct fair_ext_watchdog_report {
	char comm[TASK_COMM_LEN];
	pid_t pid;
	int cpu;
	u32 duration_ms;
};

static bool fair_ext_watchdog_check_rq(struct rq *rq,
				       struct fair_ext_watchdog_report *report,
				       unsigned long seq)
{
	unsigned long timeout = READ_ONCE(fair_ext_watchdog_timeout);
	unsigned long now = jiffies;
	struct task_struct *p;
	struct rq_flags rf;
	bool stalled = false;

	rq_lock_irqsave(rq, &rf);

	/* Do not blame fair_ext while a higher scheduling class owns the CPU. */
	if (rq->curr != current &&
	    rq->curr->sched_class != &fair_sched_class &&
	    rq->curr->sched_class != &idle_sched_class)
		goto out_unlock;

	list_for_each_entry(p, &rq->cfs_tasks, se.group_node) {
		if (p->se.sched_delayed || task_has_idle_policy(p))
			continue;

		/* A task which owns the CPU cannot be stalled. */
		if (task_on_cpu(rq, p) || task_current_donor(rq, p)) {
			fair_ext_watchdog_reset(p, now, seq);
			continue;
		}

		if (!fair_ext_watchdog_stalled(p, now, timeout, seq))
			continue;

		get_task_comm(report->comm, p);
		report->pid = task_pid_nr(p);
		report->cpu = cpu_of(rq);
		report->duration_ms =
			jiffies_to_msecs(now - p->scx.fair_ext_watchdog.at);
		stalled = true;
		break;
	}

out_unlock:
	rq_unlock_irqrestore(rq, &rf);
	return stalled;
}

static bool
fair_ext_watchdog_disable(struct sched_ext_ops *ops,
			  const struct fair_ext_watchdog_report *report)
{
	bool disabled = false;

	scoped_guard(mutex, &fair_ext_mutex) {
		if (fair_ext_registered_ops == ops &&
		    rcu_access_pointer(fair_ext_ops) == ops) {
			fair_ext_disable_callbacks(ops);
			RCU_INIT_POINTER(fair_ext_ops, NULL);
			disabled = true;
		}
	}

	if (!disabled)
		return false;

	synchronize_rcu();
	pr_err("fair_ext: %s[%d] on CPU %d failed to run for %u.%03us; disabling extension\n",
	       report->comm, report->pid, report->cpu,
	       report->duration_ms / 1000, report->duration_ms % 1000);
	return true;
}

static int fair_ext_watchdog(void *data)
{
	struct sched_ext_ops *ops = data;
	unsigned long interval = max(READ_ONCE(fair_ext_watchdog_timeout) / 2,
				     1UL);

	while (!kthread_should_stop()) {
		struct fair_ext_watchdog_report report;
		unsigned long seq;
		int cpu;

		schedule_timeout_interruptible(interval);
		if (kthread_should_stop())
			break;

		seq = atomic_long_inc_return(&fair_ext_watchdog_seq);
		for_each_online_cpu(cpu) {
			if (fair_ext_watchdog_check_rq(cpu_rq(cpu), &report,
						       seq)) {
				fair_ext_watchdog_disable(ops, &report);
				while (!kthread_should_stop())
					schedule_timeout_interruptible(MAX_SCHEDULE_TIMEOUT);
				return 0;
			}
			cond_resched();
		}
	}

	return 0;
}

__bpf_kfunc_start_defs();

/**
 * scx_fair_bpf_select_cpu - run fair CPU selection on a CPU subset
 * @p: task being placed
 * @prev_cpu: CPU previously used by @p
 * @wake_flags: wakeup flags supplied to sched_ext_ops.fair_select_cpu()
 * @preferred_mask__nullable: CPUs that fair may consider, or NULL to use the
 * task's effective affinity mask
 *
 * This kfunc is available only from sched_ext_ops.fair_select_cpu(). The mask is
 * intersected with the task's affinity mask. Returns the CPU selected by fair,
 * or a negative errno if the effective mask is empty or the call is made
 * outside the placement callback.
 */
__bpf_kfunc s32
scx_fair_bpf_select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags,
			const struct cpumask *preferred_mask__nullable)
{
	struct fair_ext_select_ctx *ctx;
	struct cpumask *effective;

	lockdep_assert_preemption_disabled();

	ctx = this_cpu_ptr(&fair_ext_select_ctx);
	if (unlikely(ctx->p != p))
		return -EPERM;
	if (prev_cpu < 0 || prev_cpu >= nr_cpu_ids)
		return -EINVAL;
	if (!preferred_mask__nullable)
		return select_task_rq_fair_mask(p, prev_cpu, wake_flags, NULL);

	effective = this_cpu_cpumask_var_ptr(fair_ext_preferred_mask);
	if (!cpumask_and(effective, preferred_mask__nullable, p->cpus_ptr))
		return -EINVAL;

	return select_task_rq_fair_mask(p, prev_cpu, wake_flags, effective);
}

/**
 * scx_fair_bpf_cpu_idle - test whether a CPU is available idle
 * @cpu: CPU to inspect
 *
 * This kfunc is available only from sched_ext_ops.fair_select_cpu(). Returns one if
 * @cpu is active and currently available idle, zero if it is busy, or a
 * negative errno if the CPU is invalid, inactive, or the call is made outside
 * the placement callback.
 */
__bpf_kfunc s32 scx_fair_bpf_cpu_idle(s32 cpu)
{
	struct fair_ext_select_ctx *ctx;

	lockdep_assert_preemption_disabled();

	ctx = this_cpu_ptr(&fair_ext_select_ctx);
	if (unlikely(!ctx->p))
		return -EPERM;
	if (cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;
	if (!cpu_active(cpu))
		return -ENODEV;

	return available_idle_cpu(cpu);
}

/**
 * scx_fair_bpf_has_idle_cpu - test whether a CPU subset has idle capacity
 * @preferred_mask: CPUs to inspect
 *
 * This kfunc is available only from sched_ext_ops.fair_balance(). Returns one if an
 * active CPU in @preferred_mask is currently available idle, zero otherwise,
 * or -EPERM if called outside the balance callback.
 */
__bpf_kfunc s32
scx_fair_bpf_has_idle_cpu(const struct cpumask *preferred_mask)
{
	struct fair_ext_balance_call_ctx *ctx;
	int cpu;

	lockdep_assert_preemption_disabled();

	ctx = this_cpu_ptr(&fair_ext_balance_call_ctx);
	if (unlikely(!ctx->active))
		return -EPERM;
	if (!preferred_mask)
		return -EINVAL;

	for_each_cpu_and(cpu, preferred_mask, cpu_active_mask) {
		if (available_idle_cpu(cpu))
			return 1;
	}

	return 0;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(fair_ext_select_cpu_kfunc_ids)
BTF_ID_FLAGS(func, scx_fair_bpf_select_cpu, KF_RCU)
BTF_ID_FLAGS(func, scx_fair_bpf_cpu_idle)
BTF_KFUNCS_END(fair_ext_select_cpu_kfunc_ids)

static int fair_ext_kfunc_filter(const struct bpf_prog *prog,
				 unsigned int member_off)
{
	if (prog->type != BPF_PROG_TYPE_STRUCT_OPS)
		return -EACCES;

	/* The struct_ops association is populated after the first verifier pass. */
	if (!prog->aux->st_ops)
		return 0;

	if (prog->aux->st_ops != &bpf_sched_ext_ops)
		return -EACCES;

	return prog->aux->attach_st_ops_member_off == member_off ? 0 : -EACCES;
}

static int fair_ext_select_cpu_kfunc_filter(const struct bpf_prog *prog,
					    u32 kfunc_id)
{
	if (!btf_id_set8_contains(&fair_ext_select_cpu_kfunc_ids, kfunc_id))
		return 0;

	return fair_ext_kfunc_filter(prog,
			offsetof(struct sched_ext_ops, fair_select_cpu));
}

static const struct btf_kfunc_id_set fair_ext_select_cpu_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &fair_ext_select_cpu_kfunc_ids,
	.filter	= fair_ext_select_cpu_kfunc_filter,
};

BTF_KFUNCS_START(fair_ext_balance_kfunc_ids)
BTF_ID_FLAGS(func, scx_fair_bpf_has_idle_cpu, KF_RCU)
BTF_KFUNCS_END(fair_ext_balance_kfunc_ids)

static int fair_ext_balance_kfunc_filter(const struct bpf_prog *prog,
					 u32 kfunc_id)
{
	if (!btf_id_set8_contains(&fair_ext_balance_kfunc_ids, kfunc_id))
		return 0;

	return fair_ext_kfunc_filter(prog,
			offsetof(struct sched_ext_ops, fair_balance));
}

static const struct btf_kfunc_id_set fair_ext_balance_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &fair_ext_balance_kfunc_ids,
	.filter	= fair_ext_balance_kfunc_filter,
};

static void fair_ext_enable_callbacks(struct sched_ext_ops *ops)
{
	if (ops->fair_select_cpu) {
		static_call_update(fair_ext_select_cpu_call,
				   ops->fair_select_cpu);
		static_branch_enable(&__fair_ext_select_cpu_enabled);
	}
	if (ops->fair_select_vlag) {
		static_call_update(fair_ext_select_vlag_call,
				   ops->fair_select_vlag);
		static_branch_enable(&__fair_ext_select_vlag_enabled);
	}
	if (ops->fair_balance) {
		static_call_update(fair_ext_balance_call, ops->fair_balance);
		static_branch_enable(&__fair_ext_balance_enabled);
	}
}

static void fair_ext_disable_callbacks(struct sched_ext_ops *ops)
{
	if (ops->fair_select_cpu) {
		static_branch_disable(&__fair_ext_select_cpu_enabled);
		static_call_update(fair_ext_select_cpu_call,
				   sched_ext_ops__fair_select_cpu);
	}
	if (ops->fair_select_vlag) {
		static_branch_disable(&__fair_ext_select_vlag_enabled);
		static_call_update(fair_ext_select_vlag_call,
				   sched_ext_ops__fair_select_vlag);
	}
	if (ops->fair_balance) {
		static_branch_disable(&__fair_ext_balance_enabled);
		static_call_update(fair_ext_balance_call,
				   sched_ext_ops__fair_balance);
	}
}

bool scx_fair_registered(void)
{
	return READ_ONCE(fair_ext_registered_ops);
}

int scx_fair_reg(struct sched_ext_ops *ops, struct bpf_link *link)
{
	struct task_struct *watchdog;

	guard(mutex)(&scx_enable_mutex);
	guard(mutex)(&fair_ext_mutex);
	if (scx_enable_state() != SCX_DISABLED || fair_ext_registered_ops)
		return -EBUSY;

	watchdog = kthread_create(fair_ext_watchdog, ops,
				  "fair_ext_watchdog");
	if (IS_ERR(watchdog))
		return PTR_ERR(watchdog);
	sched_set_fifo_low(watchdog);

	fair_ext_registered_ops = ops;
	fair_ext_watchdog_task = watchdog;
	fair_ext_watchdog_timeout = ops->timeout_ms ?
		msecs_to_jiffies(ops->timeout_ms) :
		FAIR_EXT_WATCHDOG_MAX_TIMEOUT;
	/* Make samples left by a previous attachment discontinuous. */
	atomic_long_inc(&fair_ext_watchdog_seq);
	rcu_assign_pointer(fair_ext_ops, ops);
	fair_ext_enable_callbacks(ops);
	wake_up_process(watchdog);

	return 0;
}

void scx_fair_unreg(struct sched_ext_ops *ops, struct bpf_link *link)
{
	struct task_struct *watchdog;
	bool active = false;

	guard(mutex)(&scx_enable_mutex);
	scoped_guard(mutex, &fair_ext_mutex) {
		if (WARN_ON_ONCE(fair_ext_registered_ops != ops))
			return;

		watchdog = fair_ext_watchdog_task;
		fair_ext_watchdog_task = NULL;
		fair_ext_registered_ops = NULL;
		if (rcu_access_pointer(fair_ext_ops) == ops) {
			fair_ext_disable_callbacks(ops);
			RCU_INIT_POINTER(fair_ext_ops, NULL);
			active = true;
		} else {
			WARN_ON_ONCE(rcu_access_pointer(fair_ext_ops));
		}
	}
	if (watchdog)
		kthread_stop(watchdog);
	if (!active)
		return;

	/* Wait for callbacks which observed @kdata before releasing the link. */
	synchronize_rcu();
}

int scx_fair_validate(struct sched_ext_ops *ops)
{
	void (**regular_op)(void) = (void *)ops;
	bool fair_mode = ops->flags & SCX_OPS_FAIR;
	bool has_fair = ops->fair_select_cpu || ops->fair_select_vlag ||
			ops->fair_balance;
	int nr_regular_ops = SCX_MOFF_IDX(offsetof(struct sched_ext_ops,
						dispatch_max_batch));
	int i;

	if (!fair_mode)
		return has_fair ? -EINVAL : 0;

	if (!has_fair || ops->flags != SCX_OPS_FAIR)
		return -EINVAL;

	for (i = 0; i < nr_regular_ops; i++)
		if (regular_op[i])
			return -EINVAL;

	/* Deprecated regular sched_ext callbacks live after the fair methods. */
	if (ops->cpu_acquire || ops->cpu_release)
		return -EINVAL;

	if (ops->dispatch_max_batch || ops->hotplug_seq || ops->sub_cgroup_id)
		return -EINVAL;

	return 0;
}

s32 sched_ext_ops__fair_select_cpu(struct task_struct *p, s32 prev_cpu,
				   u64 wake_flags)
{
	return -1;
}

s64 sched_ext_ops__fair_select_vlag(struct task_struct *p,
				    const struct fair_ext_vlag_ctx *ctx)
{
	return ctx->vlag;
}

s32 sched_ext_ops__fair_balance(const struct fair_ext_balance_ctx *ctx)
{
	return FAIR_EXT_BALANCE_CONTINUE;
}

int __init scx_fair_init(void)
{
	int cpu, ret;

	BTF_TYPE_EMIT(enum fair_ext_wake_flags);

	for_each_possible_cpu(cpu) {
		cpumask_var_t *mask = &per_cpu(fair_ext_preferred_mask, cpu);

		if (!zalloc_cpumask_var_node(mask, GFP_KERNEL, cpu_to_node(cpu))) {
			ret = -ENOMEM;
			goto free_masks;
		}
	}

	fair_ext_kobj = kobject_create_and_add("fair_ext", kernel_kobj);
	if (!fair_ext_kobj) {
		ret = -ENOMEM;
		goto free_masks;
	}

	ret = sysfs_create_group(fair_ext_kobj, &fair_ext_attr_group);
	if (ret)
		goto put_kobj;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&fair_ext_select_cpu_kfunc_set);
	if (ret)
		goto put_kobj;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&fair_ext_balance_kfunc_set);
	if (ret)
		goto put_kobj;

	return 0;

put_kobj:
	kobject_put(fair_ext_kobj);
	fair_ext_kobj = NULL;

free_masks:
	for_each_possible_cpu(cpu)
		free_cpumask_var(per_cpu(fair_ext_preferred_mask, cpu));
	return ret;
}
