/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Base policy of scx_pvhost and scx_pvguest: one queue per CPU, ordered by
 * weighted virtual time, and CPUs that take from their LLC when their own
 * queue is empty, then from the other LLCs. Where CPUs differ in capacity,
 * tasks go to the fastest idle CPU that fits them and move off a CPU too slow
 * for them (misfit migration).
 *
 * A port of scx_rlocal (sched-ext/scx, scheds/experimental/scx_rlocal) with
 * sparkx's load balancing and capacity changes.
 *
 * - A task waits on the queue of the CPU it was placed on, so it tends to
 *   run where its cache is. A CPU with nothing queued takes the first task
 *   it may run from another queue of its LLC, else of another LLC.
 *
 * - A waking task gets an idle CPU of its LLC: its previous CPU if idle, then
 *   a fully idle core, then any idle CPU. With CPUs of different capacity, it
 *   stays on its previous CPU if idle and fast enough for it, else takes an
 *   idle CPU of the fastest tier that has one, within its LLC first.
 *
 * - A task woken synchronously by a task of another LLC goes to an idle CPU
 *   of the waker's LLC (Linux's wake_affine). Unlike sparkx, there is no
 *   wake_wide filter here.
 *
 * - A task whose slice ends with nothing else to run keeps its CPU, unless
 *   it's too big for it and a faster CPU of the LLC is idle.
 *
 * Only usable CPUs are picked or steal: all of them on the host, the
 * non-folded ones in a guest (see pv_set_usable()).
 *
 * Copyright (c) 2026 NVIDIA Corporation.
 */
#ifndef __SCX_PVSCHED_BPF_H
#define __SCX_PVSCHED_BPF_H

/* Slice of every task, set by the loader (scx_rlocal's default) */
const volatile u64 slice_ns = 5ULL * 1000 * 1000;
#define PV_SLICE_NS	slice_ns

/* Topology, set by the loader from struct pv_topo */
const volatile u32 nr_cpu_ids = 1;
const volatile u32 nr_llcs = 1;
const volatile u32 nr_tiers = 1;
const volatile bool asym_capacity;
const volatile u32 cpu_llc[PV_MAX_CPUS];
const volatile u32 cpu_cap[PV_MAX_CPUS];
const volatile u32 cpu_tier[PV_MAX_CPUS];
/* CPUs grouped by LLC: those of LLC l from llc_cpus[llc_start[l]] */
const volatile u16 llc_cpus[PV_MAX_CPUS];
const volatile u32 llc_start[PV_MAX_LLCS + 1];
/* SMT: whether cores have several threads, and the first thread of each */
const volatile bool smt;
const volatile u16 cpu_smt_first[PV_MAX_CPUS];

/*
 * Wholly idle cores first, also outside the waker's LLC (smt_whole_core),
 * and their first thread (smt_asym_packing), set by the loader
 */
const volatile bool smt_whole_core;
const volatile bool smt_asym_packing;

_Static_assert(!(PV_MAX_CPUS & (PV_MAX_CPUS - 1)), "PV_MAX_CPUS must be a power of 2");

/*
 * Index of @cpu in a per-CPU array. Callers check the range, but clang can
 * reload the CPU from a 32-bit stack slot between the check and the access,
 * and the verifier doesn't tie that reload to the check. The mask is a no-op
 * for a checked CPU, and the barrier keeps clang from dropping it.
 */
#define CPU_IDX(cpu)							\
	({								\
		u32 __cpu = (cpu);					\
									\
		barrier_var(__cpu);					\
		__cpu & (PV_MAX_CPUS - 1);				\
	})

/*
 * Time @cpu lost to something else so far, that its tasks aren't charged
 * for. Defined by each scheduler: in a guest, the time the host made the vCPU
 * wait for a host CPU.
 */
static u64 pv_cpu_steal(s32 cpu);

/* The highest virtual time that ran on every CPU: where its queue is */
u64 cpu_vtime_now[PV_MAX_CPUS];
u64 nr_enq_blocked;	/* out: mutex-blocked proxy donors enqueued */

/*
 * With SCX_OPS_ENQ_BLOCKED, a task blocked on a kernel mutex stays runnable
 * as a proxy donor: when picked, it lends its slice to the mutex owner.
 * Donors are queued like any other task.
 */
static void pv_count_blocked(u64 enq_flags)
{
	if (enq_flags & SCX_ENQ_BLOCKED)
		__sync_fetch_and_add(&nr_enq_blocked, 1);
}

struct task_ctx {
	u64 vtime;
	u64 started_at;		/* last time it got a CPU */
	u64 steal_at;		/* pv_cpu_steal() of that CPU then */
	/*
	 * Its use of a CPU, 1024 for all of the fastest one's: of each period
	 * from one start on a CPU to the next, the share it ran, scaled by the
	 * capacity of the CPU (as Linux's util_avg), averaged.
	 */
	u64 util;
	u64 period_at;		/* start of the current period */
	u64 ran;		/* scaled run time in the current period */
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctxs SEC(".maps");

/*
 * Masks of usable CPUs: all of them, of every LLC, of every capacity tier, of
 * every tier within every LLC, and the first threads of all cores and of the
 * cores of every LLC.
 */
#define MASK_USABLE		0
#define MASK_LLC(l)		(1 + (l))
#define MASK_TIER(t)		(1 + PV_MAX_LLCS + (t))
#define MASK_LLC_TIER(l, t)	(1 + PV_MAX_LLCS + PV_MAX_TIERS + (l) * PV_MAX_TIERS + (t))
#define MASK_FIRST		(1 + PV_MAX_LLCS + PV_MAX_TIERS + PV_MAX_LLCS * PV_MAX_TIERS)
#define MASK_LLC_FIRST(l)	(MASK_FIRST + 1 + (l))
#define NR_MASKS		(MASK_FIRST + 1 + PV_MAX_LLCS)

struct pv_mask {
	struct bpf_cpumask __kptr *mask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_MASKS);
	__type(key, u32);
	__type(value, struct pv_mask);
} pv_masks SEC(".maps");

static struct bpf_cpumask *pv_bpf_mask(u32 idx)
{
	struct pv_mask *pm = bpf_map_lookup_elem(&pv_masks, &idx);

	return pm ? pm->mask : NULL;
}

static const struct cpumask *pv_mask(u32 idx)
{
	struct bpf_cpumask *mask = pv_bpf_mask(idx);

	return mask ? cast_mask(mask) : NULL;
}

static u32 llc_of(s32 cpu)
{
	return cpu >= 0 && cpu < PV_MAX_CPUS ? cpu_llc[CPU_IDX(cpu)] % PV_MAX_LLCS : 0;
}

static u32 tier_of(s32 cpu)
{
	return cpu >= 0 && cpu < PV_MAX_CPUS ? cpu_tier[CPU_IDX(cpu)] % PV_MAX_TIERS : 0;
}

static bool pv_usable(s32 cpu)
{
	const struct cpumask *usable = pv_mask(MASK_USABLE);

	return usable && cpu >= 0 && bpf_cpumask_test_cpu(cpu, usable);
}

/* Add @cpu to, or remove it from, every mask it belongs to */
static void pv_set_usable(u32 cpu, bool usable)
{
	bool first = cpu_smt_first[CPU_IDX(cpu)] == cpu;
	u32 idx[6] = {
		MASK_USABLE,
		MASK_LLC(llc_of(cpu)),
		MASK_TIER(tier_of(cpu)),
		MASK_LLC_TIER(llc_of(cpu), tier_of(cpu)),
		first ? MASK_FIRST : NR_MASKS,
		first ? MASK_LLC_FIRST(llc_of(cpu)) : NR_MASKS,
	};
	struct bpf_cpumask *mask;
	u32 i;

	bpf_for(i, 0, 6) {
		mask = pv_bpf_mask(idx[i]);
		if (!mask)
			continue;
		if (usable)
			bpf_cpumask_set_cpu(cpu, mask);
		else
			bpf_cpumask_clear_cpu(cpu, mask);
	}
}

static struct task_ctx *task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctxs, p, 0, 0);
}

/* @p's use of a CPU fits @cpu's capacity, with Linux's margin of a fifth */
static bool fits(struct task_struct *p, s32 cpu)
{
	struct task_ctx *tctx = task_ctx(p);

	return !tctx || cpu < 0 || cpu >= PV_MAX_CPUS ||
	       tctx->util * 1280 < (u64)cpu_cap[CPU_IDX(cpu)] * 1024;
}

/*
 * Claim an idle usable CPU of @mask for @p, @prev and its core first, only
 * one of a wholly idle core with SCX_PICK_IDLE_CORE in @flags
 */
static s32 pick_in_flags(struct task_struct *p, s32 prev, u64 wake_flags, u32 mask_idx,
			 u64 flags)
{
	const struct cpumask *mask = pv_mask(mask_idx);

	if (!mask)
		return -ENOENT;
	return scx_bpf_select_cpu_and(p, prev, wake_flags, mask, flags);
}

static s32 pick_in(struct task_struct *p, s32 prev, u64 wake_flags, u32 mask_idx)
{
	return pick_in_flags(p, prev, wake_flags, mask_idx, 0);
}

/*
 * Claim a CPU of a wholly idle core for a waking task: an idle thread of a
 * busy core shares it with the thread running there, and slows it down.
 * @prev's core first, then a core of its LLC and, with smt_whole_core, any
 * core, giving up cache locality for core throughput. With smt_asym_packing,
 * the core's first thread.
 */
static s32 pick_whole_core(struct task_struct *p, s32 prev, u64 wake_flags)
{
	const struct cpumask *idle_smt;
	u32 llc = llc_of(prev);
	bool core_idle;
	s32 cpu;

	if (!smt_asym_packing) {
		cpu = pick_in_flags(p, prev, wake_flags, MASK_LLC(llc), SCX_PICK_IDLE_CORE);
		if (cpu >= 0 || !smt_whole_core)
			return cpu;
		return pick_in_flags(p, prev, wake_flags, MASK_USABLE, SCX_PICK_IDLE_CORE);
	}

	/* The first thread isn't in @prev's place in the masks: try its core here */
	idle_smt = scx_bpf_get_idle_smtmask();
	core_idle = prev >= 0 && bpf_cpumask_test_cpu(prev, idle_smt);
	scx_bpf_put_idle_cpumask(idle_smt);
	if (core_idle) {
		cpu = cpu_smt_first[CPU_IDX(prev)];
		if (pv_usable(cpu) && bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
		    scx_bpf_test_and_clear_cpu_idle(cpu))
			return cpu;
	}
	cpu = pick_in_flags(p, prev, wake_flags, MASK_LLC_FIRST(llc), SCX_PICK_IDLE_CORE);
	if (cpu >= 0 || !smt_whole_core)
		return cpu;
	return pick_in_flags(p, prev, wake_flags, MASK_FIRST, SCX_PICK_IDLE_CORE);
}

/*
 * Claim an idle CPU for a waking task, the fastest capacity tier first,
 * within @prev's LLC before any other: a task leaves its cache for a faster
 * CPU, not for one as fast elsewhere. A task that @prev is fast enough for
 * stays there if it's idle.
 */
static s32 pick_fastest(struct task_struct *p, s32 prev, u64 wake_flags)
{
	u32 llc = llc_of(prev), t;
	s32 cpu;

	if (fits(p, prev) && pv_usable(prev) && bpf_cpumask_test_cpu(prev, p->cpus_ptr) &&
	    scx_bpf_test_and_clear_cpu_idle(prev))
		return prev;
	bpf_arena_for(t, 0, nr_tiers) {
		cpu = pick_in(p, prev, wake_flags, MASK_LLC_TIER(llc, t % PV_MAX_TIERS));
		if (cpu >= 0)
			return cpu;
	}
	bpf_arena_for(t, 0, nr_tiers) {
		cpu = pick_in(p, prev, wake_flags, MASK_TIER(t % PV_MAX_TIERS));
		if (cpu >= 0)
			return cpu;
	}
	return -EBUSY;
}

/* Claim an idle CPU of @prev's LLC for a waking task, @prev first */
static s32 pick_idle(struct task_struct *p, s32 prev, u64 wake_flags)
{
	s32 waker = bpf_get_smp_processor_id();
	u32 t;
	s32 cpu;

	if (smt && (smt_whole_core || smt_asym_packing)) {
		cpu = pick_whole_core(p, prev, wake_flags);
		if (cpu >= 0)
			return cpu;
	}
	/*
	 * Woken by a task of another LLC that waits for it: an idle CPU of the
	 * waker's LLC, the fastest first.
	 */
	if ((wake_flags & SCX_WAKE_SYNC) && llc_of(waker) != llc_of(prev)) {
		bpf_arena_for(t, 0, nr_tiers) {
			cpu = pick_in(p, waker, wake_flags,
				      MASK_LLC_TIER(llc_of(waker), t % PV_MAX_TIERS));
			if (cpu >= 0)
				return cpu;
		}
	}
	if (asym_capacity)
		return pick_fastest(p, prev, wake_flags);
	return pick_in(p, prev, wake_flags, MASK_LLC(llc_of(prev)));
}

/* Claim an idle faster CPU of @cpu's LLC for @p that is too big for @cpu */
static s32 pick_faster(struct task_struct *p, s32 cpu)
{
	u32 t;
	s32 faster;

	if (fits(p, cpu))
		return -EBUSY;
	bpf_arena_for(t, 0, tier_of(cpu)) {
		faster = pick_in(p, cpu, 0, MASK_LLC_TIER(llc_of(cpu), t % PV_MAX_TIERS));
		if (faster >= 0)
			return faster;
	}
	return -EBUSY;
}

/*
 * Claim an idle CPU to take a task queued on @cpu: of its LLC, else of
 * another, the fastest tier first where the CPUs differ.
 */
static s32 pick_taker(struct task_struct *p, s32 cpu)
{
	u32 t;
	s32 taker;

	if (!asym_capacity) {
		taker = pick_in(p, cpu, 0, MASK_LLC(llc_of(cpu)));
		return taker >= 0 ? taker : pick_in(p, cpu, 0, MASK_USABLE);
	}
	bpf_arena_for(t, 0, nr_tiers) {
		taker = pick_in(p, cpu, 0, MASK_LLC_TIER(llc_of(cpu), t % PV_MAX_TIERS));
		if (taker >= 0)
			return taker;
	}
	bpf_arena_for(t, 0, nr_tiers) {
		taker = pick_in(p, cpu, 0, MASK_TIER(t % PV_MAX_TIERS));
		if (taker >= 0)
			return taker;
	}
	return -EBUSY;
}

/*
 * Take a task for @cpu from another queue of its LLC, else from the other
 * LLCs, the following ones first. In llc_cpus[], the CPUs of the other LLCs
 * follow those of @cpu's LLC, wrapping around. Within the LLC, every CPU
 * starts from a different peer.
 */
static bool pv_steal(s32 cpu)
{
	u32 llc = llc_of(cpu), first = llc_start[llc], nr = llc_start[llc + 1] - first, i;
	s32 peer;

	bpf_arena_for(i, 0, nr) {
		peer = llc_cpus[(first + (cpu + i) % nr) % PV_MAX_CPUS];
		if (peer != cpu && scx_bpf_dsq_move_to_local(peer, 0))
			return true;
	}
	if (nr_llcs == 1)
		return false;
	bpf_arena_for(i, nr, nr_cpu_ids) {
		peer = llc_cpus[(first + i) % nr_cpu_ids % PV_MAX_CPUS];
		if (scx_bpf_dsq_move_to_local(peer, 0))
			return true;
	}
	return false;
}

/*
 * Queue @p on @cpu's queue. A task that wakes starts at the clock of the
 * queue, neither owed nor owing, as on Linux. One that comes from a queue that
 * is behind starts at most one slice behind, one from a queue that is ahead
 * at most one slice of its own ahead: the queues don't share a clock.
 */
static void pv_queue(struct task_struct *p, s32 cpu, u64 slice, u64 enq_flags, bool kick_taker)
{
	struct task_ctx *tctx = task_ctx(p);
	u64 now, floor, ceiling, vtime;
	s32 taker;

	if (!tctx || cpu < 0 || cpu >= PV_MAX_CPUS) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice, enq_flags);
		return;
	}
	now = cpu_vtime_now[CPU_IDX(cpu)];
	if (enq_flags & SCX_ENQ_WAKEUP)
		tctx->vtime = now;
	floor = now - PV_SLICE_NS;
	ceiling = now + scale_by_task_weight_inverse(p, PV_SLICE_NS);
	vtime = tctx->vtime;
	if (time_before(vtime, floor))
		vtime = floor;
	else if (time_before(ceiling, vtime))
		vtime = ceiling;
	tctx->vtime = vtime;
	scx_bpf_dsq_insert_vtime(p, cpu, slice, vtime, enq_flags);

	/* An idle CPU can take it from there */
	if (!kick_taker)
		return;
	taker = pick_taker(p, cpu);
	if (taker >= 0)
		scx_bpf_kick_cpu(taker, SCX_KICK_IDLE);
}

/*
 * Tasks are inserted into a CPU's local DSQ with SCX_ENQ_IMMED: they either
 * run on that CPU right away, or the kernel hands them back to ops.enqueue()
 * (SCX_TASK_REENQ_IMMED), for instance when the idle CPU they were given got
 * taken first or the CPU they woke up on is still busy. A task handed back
 * this many times waits in a queue instead: the kernel ejects a scheduler
 * whose tasks keep coming back.
 */
#define PV_MAX_REENQ	4

/*
 * A wakeup gets here without ops.select_cpu() when the kernel queued it to
 * the CPU the task was still running on (ttwu_queue_wakelist()). Run it there
 * if that CPU can right away, as the fair class does. Otherwise, under
 * overcommit often the case, the kernel hands it back and it looks for an
 * idle CPU, instead of waiting its turn behind the other tasks of its CPU,
 * vCPU threads on the host. The task comes back without SCX_ENQ_WAKEUP, so
 * it doesn't try again.
 */
static bool pv_try_stay(struct task_struct *p, u64 slice, u64 enq_flags)
{
	s32 cpu = scx_bpf_task_cpu(p);

	if (!(enq_flags & SCX_ENQ_WAKEUP) || __COMPAT_is_enq_cpu_selected(enq_flags) ||
	    (enq_flags & SCX_ENQ_BLOCKED) || is_migration_disabled(p) ||
	    !pv_usable(cpu) || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return false;
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, enq_flags | SCX_ENQ_IMMED);
	return true;
}

/*
 * Return true if @p, enqueued without going through ops.select_cpu(), should
 * look for an idle CPU before it's queued: a task handed back by SCX_ENQ_IMMED,
 * or any other enqueue of a task that isn't running, except for a
 * proxy-execution donor that blocked on a mutex, which only proxy execution
 * moves.
 */
static bool pv_should_migrate(struct task_struct *p, u64 enq_flags)
{
	return !__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p) &&
	       !is_migration_disabled(p) && !(enq_flags & SCX_ENQ_BLOCKED) &&
	       p->scx.reenq_cnt < PV_MAX_REENQ;
}

/*
 * Keep @p on its CPU after its slice, with nothing else to run there, unless
 * it's too big for the CPU and a faster one of the LLC is idle.
 */
static void pv_keep_last(struct task_struct *p, u64 slice, u64 enq_flags)
{
	s32 cpu = scx_bpf_task_cpu(p), faster;

	if (asym_capacity) {
		faster = pick_faster(p, cpu);
		if (faster >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | faster, slice, enq_flags);
			return;
		}
	}
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, enq_flags);
}

static void pv_running(struct task_struct *p)
{
	struct task_ctx *tctx = task_ctx(p);
	s32 cpu = scx_bpf_task_cpu(p);
	u64 now = scx_bpf_now(), period, share;

	if (!tctx)
		return;
	tctx->started_at = now;
	tctx->steal_at = pv_cpu_steal(cpu);
	/* A period ends: its share of running goes into the average */
	period = now - tctx->period_at;
	if (tctx->period_at && period) {
		share = tctx->ran * 1024 / period;
		if (share > 1024)
			share = 1024;
		tctx->util = (tctx->util * 3 + share) / 4;
	}
	tctx->period_at = now;
	tctx->ran = 0;
	if (cpu >= 0 && cpu < PV_MAX_CPUS &&
	    time_before(cpu_vtime_now[CPU_IDX(cpu)], tctx->vtime))
		cpu_vtime_now[CPU_IDX(cpu)] = tctx->vtime;
}

static void pv_stopping(struct task_struct *p)
{
	struct task_ctx *tctx = task_ctx(p);
	s32 cpu = scx_bpf_task_cpu(p);
	u64 ran, steal;

	if (!tctx)
		return;
	ran = scx_bpf_now() - tctx->started_at;
	/*
	 * Less what the CPU lost meanwhile, as with Linux's
	 * CONFIG_PARAVIRT_TIME_ACCOUNTING, often off in guest kernels: a task
	 * isn't charged for the time the host didn't run its vCPU. The task
	 * stayed on the CPU since pv_running(). A steal count that went back,
	 * reset when the host registered the guest again, doesn't count.
	 */
	steal = pv_cpu_steal(cpu) - tctx->steal_at;
	if ((s64)steal > 0)
		ran = steal < ran ? ran - steal : 0;
	if (cpu >= 0 && cpu < PV_MAX_CPUS)
		tctx->ran += ran * cpu_cap[CPU_IDX(cpu)] / 1024;
	tctx->vtime += scale_by_task_weight_inverse(p, ran);
}

static void pv_enable(struct task_struct *p)
{
	struct task_ctx *tctx = task_ctx(p);
	s32 cpu = scx_bpf_task_cpu(p);

	if (tctx && cpu >= 0 && cpu < PV_MAX_CPUS)
		tctx->vtime = cpu_vtime_now[CPU_IDX(cpu)];
}

/*
 * Called from a sleepable ops.init_task(): the task context is then allocated
 * with GFP_KERNEL. With GFP_ATOMIC, one failure among the thousands of tasks
 * that exist on a large host when the scheduler loads aborts the load.
 */
static s32 pv_init_task(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctxs, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE) ?
	       0 : -ENOMEM;
}

/* Create the per-CPU queues and the masks, with every CPU usable */
static s32 pv_init(void)
{
	struct bpf_cpumask *mask;
	struct pv_mask *pm;
	u32 i;
	s32 ret;

	bpf_for(i, 0, nr_cpu_ids) {
		ret = scx_bpf_create_dsq(i, -1);
		if (ret)
			return ret;
	}
	bpf_for(i, 0, NR_MASKS) {
		pm = bpf_map_lookup_elem(&pv_masks, &i);
		if (!pm)
			return -ENOENT;
		mask = bpf_cpumask_create();
		if (!mask)
			return -ENOMEM;
		mask = bpf_kptr_xchg(&pm->mask, mask);
		if (mask)
			bpf_cpumask_release(mask);
	}
	bpf_rcu_read_lock();
	bpf_for(i, 0, nr_cpu_ids)
		pv_set_usable(i, true);
	bpf_rcu_read_unlock();
	return 0;
}

#define PV_OPS_FLAGS	(SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_EXITING |		\
			 SCX_OPS_ENQ_MIGRATION_DISABLED | SCX_OPS_ALLOW_QUEUED_WAKEUP |	\
			 SCX_OPS_ENQ_BLOCKED)

#endif /* __SCX_PVSCHED_BPF_H */
