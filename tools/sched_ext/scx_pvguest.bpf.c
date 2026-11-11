/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Guest half of a paravirt scheduler pair, see scx_pvhost.bpf.c for the host.
 *
 * The scheduling policy is the one of scx_pvsched.bpf.h: per-CPU queues
 * ordered by virtual time, stealing within the LLC first, capacity aware. On
 * top of it, the scheduler shares a few pages with the host scheduler through
 * its arena (see scx_pv.h):
 *
 * - It reports its demand, a running average of runnable tasks, and the state
 *   of every vCPU.
 *
 * - It folds onto the number of vCPUs that the host entitles it to
 *   (target_vcpus). Only the first target_vcpus vCPUs, the usable ones, are
 *   picked for tasks and steal. Tasks queued on a folded vCPU move to a usable
 *   one, so folded vCPUs go idle and their vCPU threads stop competing for
 *   host CPUs. This is what the steal governor does from steal time (see
 *   Documentation/driver-api/steal-governor.rst), with the number given by
 *   the host instead of guessed from thresholds. Folding only pays off while
 *   the vCPUs contend on the host, so the loader decides when to fold from
 *   steal time and the host's idle CPUs, and sets the vCPUs to use
 *   (fold_limit, 0 to follow the host), see fold_step() in scx_pvguest.c.
 *
 * Tasks that can't run on a usable vCPU, like per-CPU kthreads, keep running
 * where they are.
 *
 * Everything coming from the host is used only while the host scheduler
 * runs: its header is valid and its heartbeat moves (host_ok). Without it,
 * as before the host registers the guest or while the host scheduler
 * restarts, the guest uses all its vCPUs and ignores the hints.
 *
 * Copyright (c) 2026 NVIDIA Corporation.
 */
#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>
#include "scx_pv.h"
#include "scx_pvsched.bpf.h"

char _license[] SEC("license") = "GPL";

/* Runs on vCPU 0, which is never folded, see start_timer() */
#define TIMER_NS	(5 * 1000 * 1000ULL)

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, PV_ARENA_FIRST + PV_PAGES);
} arena SEC(".maps");

int bpf_arena_import_dax(void *map, void __arena *addr, u32 page_cnt,
			 u64 src) __ksym __weak;

const volatile bool no_fold;		/* report, but use all vCPUs */
u32 fold_limit;				/* in: set by the loader, usable vCPUs, 0: the host's */
const volatile bool no_preempt_hints;	/* ignore the host's preempted flags */
const volatile bool no_idle_hints;	/* ignore the host's idle CPU count */
const volatile bool no_steal_clock;	/* charge tasks the host's steal time too */

u64 src;		/* in:  user address of the /dev/dax mapping */
s32 import_ret;		/* out: result of pv_import */
u32 guest_id;		/* out: guest index assigned by the host */
bool host_ok;		/* out: the host scheduler runs, its data is valid */
u64 host_epoch;		/* out: epoch of the host's registration */
u32 cur_target;		/* out: usable vCPUs */
u64 demand_avg;		/* out: runnable tasks, PV_DEMAND_ONE units */
u64 host_idle_sum;	/* out: idle host CPUs, summed every timer period */
u64 host_cpu_sum;	/* out: host CPUs, summed every timer period */

static bool timer_started;
UEI_DEFINE(uei);

struct pv_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct pv_timer);
} pv_timer SEC(".maps");

u64 arena_ubase;	/* in:  user address of the arena, from the loader */

/* Programs that only dereference arena pointers must still use the map */
#define arena_base()							\
	({								\
		asm volatile("" :: "r"(&arena));			\
		(void __arena *)arena_ubase;				\
	})

static struct pv_shared __arena *shm(void)
{
	return (struct pv_shared __arena *)((char __arena *)arena_base() +
					    PV_ARENA_FIRST * __PAGE_SIZE);
}

static void set_vcpu_state(s32 cpu, u32 state)
{
	if (cpu >= 0 && cpu < PV_MAX_VCPUS)
		PV_WRITE(shm()->gvcpu[cpu].state, state);
}

static bool cpu_running(s32 cpu)
{
	return cpu >= 0 && cpu < PV_MAX_VCPUS &&
	       PV_READ(shm()->gvcpu[cpu].state) == PV_VCPU_RUNNING;
}

static bool can_move(struct task_struct *p)
{
	return p->nr_cpus_allowed > 1 && !is_migration_disabled(p);
}

/* The host preempted @cpu's vCPU thread while it had work: it isn't running */
static bool vcpu_preempted(s32 cpu)
{
	if (no_preempt_hints || !host_ok || cpu < 0 || cpu >= PV_MAX_VCPUS)
		return false;
	return PV_READ(shm()->hvcpu[cpu].preempted);
}

/* What the host took from @cpu, see struct pv_host_vcpu */
static u64 pv_cpu_steal(s32 cpu)
{
	if (no_steal_clock || cpu < 0 || cpu >= PV_MAX_VCPUS)
		return 0;
	return PV_READ(shm()->hvcpu[cpu].steal_ns);
}

/* pick_running() compares a quarter of the LLC's vCPUs, at least this many */
#define PV_RUNNING_SCAN_MIN	8

/*
 * A usable vCPU with a short queue among the ones running on the host, for a
 * task that would wait behind @cpu, which the host preempted: the shortest
 * queue among some of them in @cpu's LLC, the ones that follow @cpu first,
 * stopping at an empty one. Like the fair class's idle scan, the scan is
 * bounded in proportion to the LLC, and stops early while the LLC is lightly
 * loaded.
 */
static s32 pick_running(struct task_struct *p, s32 cpu)
{
	u32 llc = llc_of(cpu), first = llc_start[llc], nr = llc_start[llc + 1] - first;
	u32 limit = nr / 4 > PV_RUNNING_SCAN_MIN ? nr / 4 : PV_RUNNING_SCAN_MIN;
	u32 i, seen = 0;
	u64 queued, best_nr = -1ULL;
	s32 best = -1, peer;

	bpf_arena_for(i, 0, nr) {
		peer = llc_cpus[(first + (cpu + i) % nr) % PV_MAX_CPUS];
		if (peer == cpu || !pv_usable(peer) || vcpu_preempted(peer) ||
		    !bpf_cpumask_test_cpu(peer, p->cpus_ptr))
			continue;
		queued = scx_bpf_dsq_nr_queued(peer);
		if (queued < best_nr) {
			best = peer;
			best_nr = queued;
			if (!queued)
				break;
		}
		if (++seen >= limit)
			break;
	}
	return best;
}

/*
 * No host CPU is idle: a halted vCPU woken for a task would only wait for one
 * on the host, and so would the task. Better queue it on a running vCPU.
 */
static bool host_saturated(void)
{
	return !no_idle_hints && host_ok && !PV_READ(shm()->host.nr_idle_pcpus);
}

/*
 * A running, not preempted vCPU for @p: its previous one, else the waker's.
 *
 * Not for a sync wakeup: its waker often keeps running instead of sleeping,
 * like a server thread that goes on with its other connections, and the tasks
 * it wakes would pile up behind it while the other vCPUs of the guest stay
 * idle. Other wakeups, like a mutex handed over, gain from keeping to the
 * vCPUs that run: fewer of them contend for the host CPUs and for the lock.
 */
static s32 pick_busy(struct task_struct *p, s32 prev, u64 wake_flags)
{
	s32 waker = bpf_get_smp_processor_id();

	if (wake_flags & SCX_WAKE_SYNC)
		return -1;
	if (pv_usable(prev) && !vcpu_preempted(prev) && cpu_running(prev) &&
	    bpf_cpumask_test_cpu(prev, p->cpus_ptr))
		return prev;
	if (pv_usable(waker) && bpf_cpumask_test_cpu(waker, p->cpus_ptr))
		return waker;
	return -1;
}

/* Take a task stuck behind a preempted vCPU, then steal as usual */
static bool steal(s32 cpu)
{
	u32 i, peer;

	if (!no_preempt_hints) {
		bpf_arena_for(i, 1, nr_cpu_ids) {
			peer = (cpu + i) % nr_cpu_ids;
			if (vcpu_preempted(peer) && scx_bpf_dsq_move_to_local(peer, 0))
				return true;
		}
	}
	return pv_steal(cpu);
}

/* Import the shared pages at the start of the arena, before attaching */
SEC("syscall")
int pv_import(void *ctx)
{
	struct pv_shared __arena *s = shm();

	import_ret = bpf_arena_import_dax(&arena, s, PV_PAGES, src);
	if (import_ret)
		return 0;
	s->guest.nr_vcpus = nr_cpu_ids;
	return 0;
}

/*
 * Start the timer on vCPU 0, which is never folded, and pin it there. A timer
 * on a folded vCPU would wake it up every period and its vCPU thread would
 * compete for host CPUs.
 */
static void start_timer(void)
{
	struct bpf_timer *timer;
	u32 key = 0;

	if (timer_started || bpf_get_smp_processor_id() != 0)
		return;
	timer = bpf_map_lookup_elem(&pv_timer, &key);
	if (timer && !bpf_timer_start(timer, TIMER_NS, BPF_F_TIMER_CPU_PIN))
		timer_started = true;
}

s32 BPF_STRUCT_OPS(pvguest_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	if (host_saturated()) {
		cpu = pick_busy(p, prev_cpu, wake_flags);
		if (cpu >= 0)
			return cpu;
	}
	/* Only usable vCPUs are picked: a task leaves a folded one here */
	cpu = pick_idle(p, prev_cpu, wake_flags);
	if (cpu >= 0) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, SCX_ENQ_IMMED);
		return cpu;
	}
	return prev_cpu;
}

void BPF_STRUCT_OPS(pvguest_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 cpu = scx_bpf_task_cpu(p), idle;
	const struct cpumask *usable;
	u32 target;

	pv_count_blocked(enq_flags);
	if (pv_usable(cpu)) {
		if (enq_flags & SCX_ENQ_LAST) {
			pv_keep_last(p, slice_ns, enq_flags);
			return;
		}
		if (pv_try_stay(p, slice_ns, enq_flags))
			return;
		/*
		 * Not while the host is saturated, as in ops.select_cpu(): a
		 * halted vCPU would only wait for a host CPU. The task stays
		 * on this vCPU, or leaves it below if the host preempted it.
		 */
		if (pv_should_migrate(p, enq_flags) && !host_saturated()) {
			idle = pick_idle(p, cpu, 0);
			if (idle >= 0) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | idle, slice_ns,
						   enq_flags | SCX_ENQ_IMMED);
				return;
			}
		}
	} else if (can_move(p)) {
		/* Off a folded vCPU: an idle usable one, else any usable one */
		idle = pick_in(p, cpu, 0, MASK_USABLE);
		if (idle >= 0 && p->scx.reenq_cnt < PV_MAX_REENQ) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | idle, slice_ns,
					   enq_flags | SCX_ENQ_IMMED);
			return;
		}
		usable = pv_mask(MASK_USABLE);
		if (usable) {
			target = bpf_cpumask_any_and_distribute(usable, p->cpus_ptr);
			if (target < nr_cpu_ids)
				cpu = target;
		}
	}
	/* Don't queue behind a vCPU that the host preempted */
	if (can_move(p) && vcpu_preempted(cpu)) {
		target = pick_running(p, cpu);
		if ((s32)target >= 0)
			cpu = target;
	}
	pv_queue(p, cpu, slice_ns, enq_flags, !host_saturated());
	/* Only the folded vCPU itself can run a task stuck there */
	if (!pv_usable(cpu))
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(pvguest_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * A folded vCPU still runs what is queued on it: tasks that can't run
	 * anywhere else. It doesn't steal.
	 */
	if (!scx_bpf_dsq_move_to_local(cpu, 0) && pv_usable(cpu))
		steal(cpu);
}

void BPF_STRUCT_OPS(pvguest_running, struct task_struct *p)
{
	start_timer();
	pv_running(p);
}

void BPF_STRUCT_OPS(pvguest_stopping, struct task_struct *p, bool runnable)
{
	pv_stopping(p);
}

void BPF_STRUCT_OPS(pvguest_update_idle, s32 cpu, bool idle)
{
	/* Called on @cpu: vCPU 0 may stay idle a while before running a task */
	start_timer();
	if (!idle)
		set_vcpu_state(cpu, PV_VCPU_RUNNING);
	else
		set_vcpu_state(cpu, pv_usable(cpu) ? PV_VCPU_IDLE : PV_VCPU_FOLDED);
}

void BPF_STRUCT_OPS(pvguest_enable, struct task_struct *p)
{
	pv_enable(p);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(pvguest_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	return pv_init_task(p);
}

/* Make the first @target vCPUs usable, push tasks off the other ones */
static void apply_target(u32 target)
{
	struct pv_shared __arena *s = shm();
	u32 cpu;

	bpf_for(cpu, 0, nr_cpu_ids) {
		pv_set_usable(cpu, cpu < target);
		if (cpu < target)
			continue;
		if (cpu < PV_MAX_VCPUS && s->gvcpu[cpu].state == PV_VCPU_RUNNING)
			scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
		else
			set_vcpu_state(cpu, PV_VCPU_FOLDED);
	}
	cur_target = target;
}

static u64 host_seq, host_seen_at, seen_epoch;

/*
 * The host's data is valid while its header is, for this version of the
 * protocol, and its heartbeat moves.
 */
static void check_host(struct pv_shared __arena *s)
{
	u64 now = scx_bpf_now(), seq;

	if (PV_READ(s->host.magic) != PV_MAGIC || PV_READ(s->host.version) != PV_VERSION) {
		host_ok = false;
		return;
	}
	seq = PV_READ(s->host.seq);
	if (seq != host_seq) {
		host_seq = seq;
		host_seen_at = now;
	}
	host_ok = now - host_seen_at < PV_HOST_STALE_NS;
	if (host_ok) {
		guest_id = PV_READ(s->host.guest_id);
		host_epoch = PV_READ(s->host.epoch);
	}
}

/* Publish the demand and follow the host's entitlement */
static int pv_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	struct pv_shared __arena *s = shm();
	u32 cpu, busy = 0, target;
	u64 queued = 0, sample;
	s32 nr;

	check_host(s);
	/*
	 * A new host registration, after a migration or a host restart: the
	 * pages may not hold what this guest wrote once, as when a migration
	 * doesn't copy them, write it again, the folded vCPUs too.
	 */
	if (host_ok && host_epoch != seen_epoch) {
		seen_epoch = host_epoch;
		PV_WRITE(s->guest.nr_vcpus, nr_cpu_ids);
		PV_WRITE(s->guest.ready, PV_GUEST_READY);
		cur_target = 0;
	}

	bpf_for(cpu, 0, nr_cpu_ids) {
		if (cpu >= PV_MAX_VCPUS)
			break;
		if (s->gvcpu[cpu].state == PV_VCPU_RUNNING)
			busy++;
		/* Negative once the DSQs are gone, while the scheduler exits */
		nr = scx_bpf_dsq_nr_queued(cpu);
		if (nr > 0)
			queued += nr;
	}
	if (host_ok) {
		host_idle_sum += PV_READ(s->host.nr_idle_pcpus);
		host_cpu_sum += PV_READ(s->host.nr_pcpus);
	}
	sample = (busy + queued) << PV_DEMAND_SHIFT;
	/* Average over ~8 periods, enough to ride out short bursts */
	demand_avg = (demand_avg * 7 + sample) / 8;
	PV_WRITE(s->guest.demand, demand_avg);

	target = host_ok ? PV_READ(s->host.target_vcpus) : 0;
	if (fold_limit)
		target = fold_limit;
	if (!target || target > nr_cpu_ids || no_fold)
		target = nr_cpu_ids;
	if (target != cur_target)
		apply_target(target);
	PV_WRITE(s->guest.nr_folded, nr_cpu_ids - target);
	PV_WRITE(s->guest.seq, s->guest.seq + 1);

	bpf_timer_start(timer, TIMER_NS, BPF_F_TIMER_CPU_PIN);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(pvguest_init)
{
	struct pv_shared __arena *s = shm();
	struct bpf_timer *timer;
	u32 key = 0;
	s32 ret;

	if (nr_cpu_ids > PV_MAX_VCPUS)
		return -E2BIG;
	ret = pv_init();
	if (ret)
		return ret;
	cur_target = nr_cpu_ids;

	timer = bpf_map_lookup_elem(&pv_timer, &key);
	if (!timer)
		return -ESRCH;
	bpf_timer_init(timer, &pv_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, pv_timerfn);

	PV_WRITE(s->guest.ready, PV_GUEST_READY);
	return 0;
}

void BPF_STRUCT_OPS(pvguest_exit, struct scx_exit_info *ei)
{
	/* The host stops looking at our hints and entitlement */
	PV_WRITE(shm()->guest.ready, 0);
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(pvguest_ops,
	       .select_cpu		= (void *)pvguest_select_cpu,
	       .enqueue			= (void *)pvguest_enqueue,
	       .dispatch		= (void *)pvguest_dispatch,
	       .running			= (void *)pvguest_running,
	       .stopping		= (void *)pvguest_stopping,
	       .update_idle		= (void *)pvguest_update_idle,
	       .enable			= (void *)pvguest_enable,
	       .init_task		= (void *)pvguest_init_task,
	       .init			= (void *)pvguest_init,
	       .exit			= (void *)pvguest_exit,
	       .flags			= PV_OPS_FLAGS | SCX_OPS_KEEP_BUILTIN_IDLE,
	       .name			= "pvguest");
