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

#include "sched.h"

static s32 sched_fair_ops__select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags);
static s32 sched_fair_ops__balance(const struct fair_ext_balance_ctx *ctx);

static struct bpf_struct_ops bpf_sched_fair_ops;

enum fair_ext_wake_flags {
	/* expose select WF_* flags as enums */
	FAIR_EXT_WAKE_EXEC		= WF_EXEC,
	FAIR_EXT_WAKE_FORK		= WF_FORK,
	FAIR_EXT_WAKE_TTWU		= WF_TTWU,
	FAIR_EXT_WAKE_SYNC		= WF_SYNC,
	FAIR_EXT_WAKE_CURRENT_CPU	= WF_CURRENT_CPU,
};

static DEFINE_MUTEX(fair_ext_mutex);
static struct sched_fair_ops __rcu *fair_ext_ops;
static struct sched_fair_ops *fair_ext_registered_ops;
static struct kobject *fair_ext_kobj;

struct fair_ext_select_ctx {
	struct task_struct *p;
};

struct fair_ext_balance_call_ctx {
	bool active;
};

static DEFINE_PER_CPU(struct fair_ext_select_ctx, fair_ext_select_ctx);
static DEFINE_PER_CPU(struct fair_ext_balance_call_ctx, fair_ext_balance_call_ctx);
static DEFINE_PER_CPU(cpumask_var_t, fair_ext_preferred_mask);

DEFINE_STATIC_CALL(fair_ext_select_cpu_call, sched_fair_ops__select_cpu);
DEFINE_STATIC_CALL(fair_ext_balance_call, sched_fair_ops__balance);

/* Keep each fair extension hook patched out until it is registered. */
DEFINE_STATIC_KEY_FALSE(__fair_ext_select_cpu_enabled);
DEFINE_STATIC_KEY_FALSE(__fair_ext_balance_enabled);

static void fair_ext_disable_callbacks(struct sched_fair_ops *ops);

static ssize_t state_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	const char *state;

	guard(mutex)(&fair_ext_mutex);
	state = fair_ext_registered_ops ? "enabled" : "disabled";

	return sysfs_emit(buf, "%s\n", state);
}

static struct kobj_attribute state_attr = __ATTR_RO(state);

static ssize_t map_id_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
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

static enum fair_ext_idle_type fair_ext_map_idle_type(enum cpu_idle_type idle)
{
	switch (idle) {
	case __CPU_NOT_IDLE:
		return FAIR_EXT_CPU_NOT_IDLE;
	case CPU_IDLE:
		return FAIR_EXT_CPU_IDLE;
	case CPU_NEWLY_IDLE:
		return FAIR_EXT_CPU_NEWLY_IDLE;
	default:
		WARN_ON_ONCE(1);
		return FAIR_EXT_CPU_NOT_IDLE;
	}
}

bool fair_ext_balance(int cpu, enum cpu_idle_type idle)
{
	struct fair_ext_balance_ctx state = {
		.cpu = cpu,
		.idle = fair_ext_map_idle_type(idle),
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

__bpf_kfunc_start_defs();

/**
 * sched_fair_bpf_select_cpu - run fair CPU selection on a CPU subset
 * @p: task being placed
 * @prev_cpu: CPU previously used by @p
 * @wake_flags: wakeup flags supplied to sched_fair_ops.select_cpu()
 * @preferred_mask__nullable: CPUs that fair may consider, or NULL to use the
 * task's effective affinity mask
 *
 * This kfunc is available only from sched_fair_ops.select_cpu(). The mask is
 * intersected with the task's affinity mask. Returns the CPU selected by fair,
 * or a negative errno if the effective mask is empty or the call is made
 * outside the placement callback.
 */
__bpf_kfunc s32 sched_fair_bpf_select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags,
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
 * sched_fair_bpf_cpu_idle - test whether a CPU is available idle
 * @cpu: CPU to inspect
 *
 * This kfunc is available only from sched_fair_ops.select_cpu(). Returns one if
 * @cpu is active and currently available idle, zero if it is busy, or a
 * negative errno if the CPU is invalid, inactive, or the call is made outside
 * the placement callback.
 */
__bpf_kfunc s32 sched_fair_bpf_cpu_idle(s32 cpu)
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
 * sched_fair_bpf_has_idle_cpu - test whether a CPU subset has idle capacity
 * @preferred_mask: CPUs to inspect
 *
 * This kfunc is available only from sched_fair_ops.balance(). Returns one if an
 * active CPU in @preferred_mask is currently available idle, zero otherwise,
 * or -EPERM if called outside the balance callback.
 */
__bpf_kfunc s32 sched_fair_bpf_has_idle_cpu(const struct cpumask *preferred_mask)
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
BTF_ID_FLAGS(func, sched_fair_bpf_select_cpu, KF_RCU)
BTF_ID_FLAGS(func, sched_fair_bpf_cpu_idle)
BTF_KFUNCS_END(fair_ext_select_cpu_kfunc_ids)

static int fair_ext_kfunc_filter(const struct bpf_prog *prog, unsigned int member_off)
{
	if (prog->type != BPF_PROG_TYPE_STRUCT_OPS)
		return -EACCES;

	/* The struct_ops association is populated after the first verifier pass. */
	if (!prog->aux->st_ops)
		return 0;

	if (prog->aux->st_ops != &bpf_sched_fair_ops)
		return -EACCES;

	return prog->aux->attach_st_ops_member_off == member_off ? 0 : -EACCES;
}

static int fair_ext_select_cpu_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&fair_ext_select_cpu_kfunc_ids, kfunc_id))
		return 0;

	return fair_ext_kfunc_filter(prog, offsetof(struct sched_fair_ops, select_cpu));
}

static const struct btf_kfunc_id_set fair_ext_select_cpu_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &fair_ext_select_cpu_kfunc_ids,
	.filter	= fair_ext_select_cpu_kfunc_filter,
};

BTF_KFUNCS_START(fair_ext_balance_kfunc_ids)
BTF_ID_FLAGS(func, sched_fair_bpf_has_idle_cpu, KF_RCU)
BTF_KFUNCS_END(fair_ext_balance_kfunc_ids)

static int fair_ext_balance_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&fair_ext_balance_kfunc_ids, kfunc_id))
		return 0;

	return fair_ext_kfunc_filter(prog, offsetof(struct sched_fair_ops, balance));
}

static const struct btf_kfunc_id_set fair_ext_balance_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &fair_ext_balance_kfunc_ids,
	.filter	= fair_ext_balance_kfunc_filter,
};

static void fair_ext_enable_callbacks(struct sched_fair_ops *ops)
{
	if (ops->select_cpu) {
		static_call_update(fair_ext_select_cpu_call,
				   ops->select_cpu);
		static_branch_enable(&__fair_ext_select_cpu_enabled);
	}
	if (ops->balance) {
		static_call_update(fair_ext_balance_call, ops->balance);
		static_branch_enable(&__fair_ext_balance_enabled);
	}
}

static void fair_ext_disable_callbacks(struct sched_fair_ops *ops)
{
	if (ops->select_cpu) {
		static_branch_disable(&__fair_ext_select_cpu_enabled);
		static_call_update(fair_ext_select_cpu_call,
				   sched_fair_ops__select_cpu);
	}
	if (ops->balance) {
		static_branch_disable(&__fair_ext_balance_enabled);
		static_call_update(fair_ext_balance_call,
				   sched_fair_ops__balance);
	}
}

static int bpf_sched_fair_reg(void *kdata, struct bpf_link *link)
{
	struct sched_fair_ops *ops = kdata;

	guard(mutex)(&fair_ext_mutex);
	if (fair_ext_registered_ops)
		return -EBUSY;

	fair_ext_registered_ops = ops;
	rcu_assign_pointer(fair_ext_ops, ops);
	fair_ext_enable_callbacks(ops);

	return 0;
}

static void bpf_sched_fair_unreg(void *kdata, struct bpf_link *link)
{
	struct sched_fair_ops *ops = kdata;
	bool active = false;

	scoped_guard(mutex, &fair_ext_mutex) {
		if (WARN_ON_ONCE(fair_ext_registered_ops != ops))
			return;

		fair_ext_registered_ops = NULL;
		if (rcu_access_pointer(fair_ext_ops) == ops) {
			fair_ext_disable_callbacks(ops);
			RCU_INIT_POINTER(fair_ext_ops, NULL);
			active = true;
		} else {
			WARN_ON_ONCE(rcu_access_pointer(fair_ext_ops));
		}
	}

	if (!active)
		return;

	/* Wait for callbacks which observed @kdata before releasing the link. */
	synchronize_rcu();
}

static int bpf_sched_fair_init_member(const struct btf_type *t,
				      const struct btf_member *member,
				      void *kdata, const void *udata)
{
	const struct sched_fair_ops *uops = udata;
	struct sched_fair_ops *ops = kdata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;
	int ret;

	if (moff != offsetof(struct sched_fair_ops, name))
		return 0;

	ret = bpf_obj_name_cpy(ops->name, uops->name, sizeof(ops->name));
	if (ret <= 0)
		return ret ?: -EINVAL;

	return 1;
}

static int bpf_sched_fair_validate(void *kdata)
{
	struct sched_fair_ops *ops = kdata;

	if (!ops->select_cpu && !ops->balance)
		return -EINVAL;

	return 0;
}

static bool bpf_sched_fair_is_valid_access(int off, int size, enum bpf_access_type type,
					   const struct bpf_prog *prog,
					   struct bpf_insn_access_aux *info)
{
	if (type != BPF_READ)
		return false;
	if (off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS)
		return false;
	if (off % size)
		return false;

	return btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_verifier_ops bpf_sched_fair_verifier_ops = {
	.get_func_proto	= bpf_base_func_proto,
	.is_valid_access = bpf_sched_fair_is_valid_access,
};

static int bpf_sched_fair_init(struct btf *btf)
{
	return 0;
}

static s32 sched_fair_ops__select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	return -1;
}

static s32 sched_fair_ops__balance(const struct fair_ext_balance_ctx *ctx)
{
	return FAIR_EXT_BALANCE_CONTINUE;
}

static struct sched_fair_ops __bpf_ops_sched_fair_ops = {
	.select_cpu	= sched_fair_ops__select_cpu,
	.balance	= sched_fair_ops__balance,
};

static struct bpf_struct_ops bpf_sched_fair_ops = {
	.verifier_ops	= &bpf_sched_fair_verifier_ops,
	.init		= bpf_sched_fair_init,
	.reg		= bpf_sched_fair_reg,
	.unreg		= bpf_sched_fair_unreg,
	.init_member	= bpf_sched_fair_init_member,
	.validate	= bpf_sched_fair_validate,
	.name		= "sched_fair_ops",
	.owner		= THIS_MODULE,
	.cfi_stubs	= &__bpf_ops_sched_fair_ops,
};

static int __init fair_ext_init(void)
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

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &fair_ext_select_cpu_kfunc_set);
	if (ret)
		goto put_kobj;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &fair_ext_balance_kfunc_set);
	if (ret)
		goto put_kobj;

	ret = register_bpf_struct_ops(&bpf_sched_fair_ops, sched_fair_ops);
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
late_initcall(fair_ext_init);
