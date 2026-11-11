/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Host half of a paravirt scheduler pair, see scx_pvguest.bpf.c for the guest.
 *
 * The scheduling policy is the one of scx_pvsched.bpf.h: per-CPU queues
 * ordered by virtual time, stealing within the LLC first, capacity aware. On
 * top of it, the scheduler shares a few pages with every guest scheduler
 * through its arena (see scx_pv.h). The guest in slot i owns PV_PAGES pages
 * at arena page PV_ARENA_FIRST + i * PV_PAGES, imported at runtime by the
 * loader from the file that the VMM uses as the guest's virtio-pmem or NVDIMM
 * device, and released when the VM goes away. slot_live[] says which slots
 * hold pages.
 *
 * - Entitlement: guests report their demand, a running average of runnable
 *   tasks. Every millisecond the host divides nr_pcpus host CPUs between them
 *   (max-min fairness: nobody gets more than it asks for, what is left goes
 *   to the others) and publishes each guest's share as target_vcpus. Without
 *   contention, target_vcpus is 0 and guests use all their vCPUs. Guests fold
 *   onto target_vcpus vCPUs, so vCPU threads stop preempting each other on
 *   the host, the problem the steal governor addresses with steal time.
 *
 * - Preemption: when the vCPU thread of a busy vCPU is preempted on the host,
 *   the guest sees it in the vCPU's preempted flag.
 *
 * - Steal: the host adds the time every vCPU thread waits for a host CPU to
 *   the vCPU's steal_ns, and the guest doesn't charge it to its tasks.
 *
 * - Fairness per guest: the host scheduler is fair between tasks, so a guest
 *   that doesn't run the guest scheduler, and keeps all its vCPUs busy, would
 *   take the CPU time that the guests that fold give up. Such a guest counts
 *   in the division by its runnable vCPU threads, and the host holds it to its
 *   share itself: at most that many of its vCPU threads run at once. The
 *   others wait in a queue of the guest, unless a host CPU would stay idle:
 *   then they borrow it for a short slice, and give it back as soon as
 *   another task wants it (-T: fairness per task only, as without
 *   paravirt).
 *
 * - Folded vCPUs: the vCPU threads of folded vCPUs only wake up for guest
 *   housekeeping (interrupts, IPIs, timers) and get a short slice. They are
 *   not queued behind the others: the guest kernel may be waiting for them,
 *   e.g. for a TLB shootdown, and delaying them shows up as steal time and
 *   slows down the whole guest.
 *
 * The loader maps the vCPU threads of every guest (the "CPU n/KVM" threads of
 * QEMU, "fc_vcpu n" of Firecracker) to their guest and vCPU index in
 * vcpu_threads. A guest only counts while its scheduler runs: ready, and its
 * heartbeat moving.
 *
 * The VMM may write the shared pages too: an incoming migration copies the
 * source host's header over the one written at registration. The host writes
 * its own back, so that the guest sees a new epoch and starts over.
 *
 * Copyright (c) 2026 NVIDIA Corporation.
 */
#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>
#include "scx_pv.h"
#include "scx_pvsched.bpf.h"

char _license[] SEC("license") = "GPL";

#define TIMER_NS	(1000 * 1000ULL)

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, PV_ARENA_FIRST + PV_PAGES * PV_MAX_GUESTS);
} arena SEC(".maps");

int bpf_arena_import_memfd(void *map, void __arena *addr, u32 page_cnt,
			   int fd, u64 off) __ksym __weak;

struct vcpu_id {
	u32 guest;
	u32 vcpu;
};

/* Thread ID of a vCPU thread -> its guest and vCPU index */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PV_MAX_GUESTS * PV_MAX_VCPUS);
	__type(key, u32);
	__type(value, struct vcpu_id);
} vcpu_threads SEC(".maps");

const volatile u32 nr_pcpus = 1;
/* Host CPUs the guests run on, all of them if nr_pool_cpus is 0 */
const volatile u32 nr_pool_cpus;
const volatile u32 pool_cpus[PV_MAX_CPUS];

s32 import_fd;		/* in:  the guest's file, imported from PV_DAX_OFF */
u32 import_guest;	/* in:  slot to import or release */
s32 import_ret;		/* out: result of pv_import */
u8 slot_live[PV_MAX_GUESTS];	/* in:  the slot holds imported pages */
u32 slot_vcpus[PV_MAX_GUESTS];	/* in:  vCPU threads found in the slot's VMM */
u64 slot_epoch[PV_MAX_GUESTS];	/* in:  epoch of the slot's registration */
u64 nr_folded_runs;	/* out: vCPU threads of folded vCPUs queued */

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

static struct pv_shared __arena *shm(u32 guest)
{
	return (struct pv_shared __arena *)((char __arena *)arena_base() +
					    (PV_ARENA_FIRST + (u64)guest * PV_PAGES) *
					    __PAGE_SIZE);
}

static bool slot_used(u32 g)
{
	return g < PV_MAX_GUESTS && READ_ONCE(slot_live[g]);
}

/* Heartbeat of every guest, updated by update_targets() */
static u64 guest_seq[PV_MAX_GUESTS];
static u64 guest_seen_at[PV_MAX_GUESTS];

/* The guest scheduler runs: ready, and its heartbeat recently moved */
static bool guest_alive(u32 g)
{
	return slot_used(g) && PV_READ(shm(g)->guest.ready) == PV_GUEST_READY &&
	       scx_bpf_now() - guest_seen_at[g] < PV_GUEST_STALE_NS;
}

/* The vCPU of @p if it is a vCPU thread of a registered guest */
static struct vcpu_id *vcpu_of(struct task_struct *p)
{
	u32 tid = p->pid;
	struct vcpu_id *id = bpf_map_lookup_elem(&vcpu_threads, &tid);

	if (!id || !slot_used(id->guest) || id->vcpu >= PV_MAX_VCPUS)
		return NULL;
	return id;
}

static bool is_folded_vcpu(struct task_struct *p)
{
	struct vcpu_id *id = vcpu_of(p);

	return id && guest_alive(id->guest) &&
	       PV_READ(shm(id->guest)->gvcpu[id->vcpu].state) == PV_VCPU_FOLDED;
}

/* The host's own CPUs lose nothing worth tracking */
static u64 pv_cpu_steal(s32 cpu)
{
	return 0;
}

/*
 * Since when every vCPU thread waits for a host CPU, 0 while it doesn't: from
 * a wakeup or a preemption to the next time it runs, what KVM reports as
 * steal time.
 */
static u64 vcpu_wait_at[PV_MAX_GUESTS * PV_MAX_VCPUS];

static u64 *wait_at(struct vcpu_id *id)
{
	return &vcpu_wait_at[(id->guest * PV_MAX_VCPUS + id->vcpu) &
			     (PV_MAX_GUESTS * PV_MAX_VCPUS - 1)];
}

const volatile bool vm_fair = true;	/* off with -T */

/* Which vCPU threads are runnable, for the guests without a scheduler */
static u8 vcpu_runnable[PV_MAX_GUESTS * PV_MAX_VCPUS];

static u8 *runnable_flag(struct vcpu_id *id)
{
	return &vcpu_runnable[(id->guest * PV_MAX_VCPUS + id->vcpu) &
			      (PV_MAX_GUESTS * PV_MAX_VCPUS - 1)];
}

/* vCPU threads of folded vCPUs only serve guest housekeeping */
static u64 task_slice(struct task_struct *p)
{
	if (!is_folded_vcpu(p))
		return slice_ns;
	__sync_fetch_and_add(&nr_folded_runs, 1);
	return slice_ns / 4;
}

/*
 * A guest that doesn't run the guest scheduler doesn't fold onto its share of
 * the host CPUs, so the host holds it to that share itself: at most
 * guest_cap[g] of its vCPU threads run at once, the others wait in the
 * guest's own DSQ, ordered by virtual time. 0: no cap.
 */
#define GUEST_DSQ(g)	(1ULL << 32 | (g))

static u32 guest_cap[PV_MAX_GUESTS];
static u32 guest_running[PV_MAX_GUESTS];
/* Directed yield target waiting in every guest's DSQ, see pvhost_yield() */
static u32 guest_yield_pid[PV_MAX_GUESTS];
u64 nr_capped;		/* out: vCPU threads held back by their guest's cap */
u64 nr_borrows;		/* out: vCPU threads run over their guest's cap */

/*
 * The cap doesn't leave host CPUs idle: a vCPU thread over it may still run
 * on a CPU that nothing else wants, for a short slice, and is preempted as
 * soon as another task is queued for that CPU. borrowed_mask says which CPUs
 * run one.
 */
#define BORROW_SLICE_NS	(slice_ns / 4)

private(PVHOST) struct bpf_cpumask __kptr *borrowed_mask;
static u32 nr_borrowed;

/* @p is the vCPU thread of a capped guest that must wait for its turn */
static bool must_wait(struct task_struct *p)
{
	struct vcpu_id *id;
	u32 g, cap;

	if (!vm_fair)
		return false;
	id = vcpu_of(p);
	if (!id)
		return false;
	g = id->guest % PV_MAX_GUESTS;
	cap = READ_ONCE(guest_cap[g]);
	if (!cap)
		return false;
	/* Not ahead of the ones already waiting */
	return READ_ONCE(guest_running[g]) >= cap || scx_bpf_dsq_nr_queued(GUEST_DSQ(g));
}

static void queue_capped(struct task_struct *p, u64 slice, u64 enq_flags)
{
	struct vcpu_id *id = vcpu_of(p);
	struct task_ctx *tctx = task_ctx(p);

	if (!id || !tctx) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice, enq_flags);
		return;
	}
	scx_bpf_dsq_insert_vtime(p, GUEST_DSQ(id->guest % PV_MAX_GUESTS), slice,
				 tctx->vtime, enq_flags);
	__sync_fetch_and_add(&nr_capped, 1);
}

/*
 * Run a waiting vCPU thread of a guest below its cap on @cpu, or of any guest
 * whose cap went away. The target of a directed yield goes first.
 */
static bool dispatch_capped(s32 cpu)
{
	struct task_struct *p;
	u32 g, cap, pid;

	if (!vm_fair || !pv_usable(cpu))
		return false;
	bpf_for(g, 0, PV_MAX_GUESTS) {
		if (!scx_bpf_dsq_nr_queued(GUEST_DSQ(g)))
			continue;
		cap = READ_ONCE(guest_cap[g]);
		if (cap && READ_ONCE(guest_running[g]) >= cap)
			continue;
		pid = guest_yield_pid[g];
		if (pid) {
			guest_yield_pid[g] = 0;
			bpf_for_each(scx_dsq, p, GUEST_DSQ(g), 0) {
				if (p->pid != pid)
					continue;
				if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
				    scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_LOCAL, 0))
					return true;
				break;
			}
		}
		if (scx_bpf_dsq_move_to_local(GUEST_DSQ(g), 0))
			return true;
	}
	return false;
}

/* Lend @cpu, about to go idle, to a vCPU thread waiting over its cap */
static bool dispatch_borrow(s32 cpu)
{
	struct task_struct *p;
	u32 g;

	if (!vm_fair || !pv_usable(cpu))
		return false;
	bpf_for(g, 0, PV_MAX_GUESTS) {
		if (!scx_bpf_dsq_nr_queued(GUEST_DSQ(g)))
			continue;
		bpf_for_each(scx_dsq, p, GUEST_DSQ(g), 0) {
			if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
				continue;
			scx_bpf_dsq_move_set_slice(BPF_FOR_EACH_ITER, BORROW_SLICE_NS);
			if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_LOCAL, 0))
				return true;
		}
	}
	return false;
}

/* A host CPU of the guests running a borrower that @p may preempt, or -1 */
static s32 find_borrowed(struct task_struct *p)
{
	struct bpf_cpumask *borrowed = borrowed_mask;
	u32 cpu;

	if (!vm_fair || !READ_ONCE(nr_borrowed) || must_wait(p) || !borrowed)
		return -1;
	cpu = bpf_cpumask_any_and_distribute(cast_mask(borrowed), p->cpus_ptr);
	return cpu < nr_cpu_ids ? cpu : -1;
}

/* Wake idle CPUs for the waiting vCPU threads, under their cap or not */
static void kick_capped(void)
{
	const struct cpumask *usable = pv_mask(MASK_USABLE);
	u32 g, nr, i;
	s32 cpu;

	if (!usable)
		return;
	bpf_for(g, 0, PV_MAX_GUESTS) {
		nr = scx_bpf_dsq_nr_queued(GUEST_DSQ(g));
		if (!nr)
			continue;
		bpf_for(i, 0, nr) {
			cpu = scx_bpf_pick_idle_cpu(usable, 0);
			if (cpu < 0)
				return;
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		}
	}
}

/* Import the pages of a new guest into its slot, the loader marks it live */
SEC("syscall")
int pv_import(void *ctx)
{
	import_ret = -22;
	if (import_guest < PV_MAX_GUESTS)
		import_ret = bpf_arena_import_memfd(&arena, shm(import_guest),
						    PV_PAGES, import_fd, PV_DAX_OFF);
	return 0;
}

/*
 * Release the pages of a guest that went away, once the loader cleared its
 * slot_live: a scheduler path still on the way only faults on the arena,
 * reading zeroes.
 */
SEC("syscall")
int pv_release(void *ctx)
{
	u32 v;

	if (import_guest >= PV_MAX_GUESTS)
		return 0;
	bpf_arena_free_pages(&arena, shm(import_guest), PV_PAGES);
	/* The next guest in the slot doesn't inherit the stamps */
	bpf_for(v, 0, PV_MAX_VCPUS) {
		vcpu_wait_at[(import_guest * PV_MAX_VCPUS + v) &
			     (PV_MAX_GUESTS * PV_MAX_VCPUS - 1)] = 0;
		vcpu_runnable[(import_guest * PV_MAX_VCPUS + v) &
			      (PV_MAX_GUESTS * PV_MAX_VCPUS - 1)] = 0;
	}
	guest_cap[import_guest % PV_MAX_GUESTS] = 0;
	guest_running[import_guest % PV_MAX_GUESTS] = 0;
	guest_yield_pid[import_guest % PV_MAX_GUESTS] = 0;
	return 0;
}

s32 BPF_STRUCT_OPS(pvhost_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	/* Over its guest's cap: only a CPU that would stay idle */
	if (must_wait(p)) {
		cpu = pick_idle(p, prev_cpu, wake_flags);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, BORROW_SLICE_NS, SCX_ENQ_IMMED);
			return cpu;
		}
		return prev_cpu;
	}
	cpu = pick_idle(p, prev_cpu, wake_flags);
	if (cpu >= 0) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), SCX_ENQ_IMMED);
		return cpu;
	}
	return prev_cpu;
}

void BPF_STRUCT_OPS(pvhost_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 cpu = scx_bpf_task_cpu(p), idle;
	u64 slice = task_slice(p);

	pv_count_blocked(enq_flags);
	if (must_wait(p)) {
		queue_capped(p, slice, enq_flags);
		/* An idle CPU takes it, under the cap or as a borrower */
		idle = pick_idle(p, cpu, 0);
		if (idle >= 0)
			scx_bpf_kick_cpu(idle, SCX_KICK_IDLE);
		return;
	}
	if (enq_flags & SCX_ENQ_LAST) {
		pv_keep_last(p, slice, enq_flags);
		return;
	}
	if (pv_try_stay(p, slice, enq_flags))
		return;
	if (pv_should_migrate(p, enq_flags)) {
		idle = pick_idle(p, cpu, 0);
		if (idle >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | idle, slice,
					   enq_flags | SCX_ENQ_IMMED);
			return;
		}
	}
	/* Take the CPU back from a borrower rather than wait */
	idle = find_borrowed(p);
	if (idle >= 0) {
		pv_queue(p, idle, slice, enq_flags, false);
		scx_bpf_kick_cpu(idle, SCX_KICK_PREEMPT);
		return;
	}
	pv_queue(p, cpu, slice, enq_flags, true);
}

/* Directed yield target waiting in every CPU's DSQ, see pvhost_yield() */
u32 yield_pid[PV_MAX_CPUS];
u64 nr_yields;		/* out: directed yields honored */

/* Run the target of a directed yield queued to @cpu's DSQ first */
static bool dispatch_yield_target(s32 cpu)
{
	struct task_struct *p;
	u32 pid;

	if (cpu < 0 || cpu >= PV_MAX_CPUS)
		return false;
	pid = yield_pid[CPU_IDX(cpu)];
	if (!pid)
		return false;
	yield_pid[CPU_IDX(cpu)] = 0;
	bpf_for_each(scx_dsq, p, cpu, 0) {
		if (p->pid != pid)
			continue;
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			return false;
		return scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_LOCAL, 0);
	}
	return false;
}

void BPF_STRUCT_OPS(pvhost_dispatch, s32 cpu, struct task_struct *prev)
{
	if (dispatch_yield_target(cpu))
		return;
	/*
	 * The CPU's own queue first, ordered by virtual time: a guest under its
	 * cap doesn't get ahead of the vCPU threads already waiting there.
	 */
	if (scx_bpf_dsq_move_to_local(cpu, 0) || dispatch_capped(cpu) || pv_steal(cpu))
		return;
	dispatch_borrow(cpu);
}

/*
 * A vCPU spinning on a lock exits to KVM, which yields to a preempted vCPU
 * of the same guest, likely the lock holder: kvm_vcpu_on_spin() ->
 * yield_to(). Guests without paravirt spinlocks, like arm64 ones, depend on
 * it: if the lock holder waits behind the spinners for whole slices, they
 * burn their host CPU time spinning.
 *
 * The yielding task gives its slice up. The target can't be moved from here,
 * so mark it: the next ops.dispatch() of the CPU whose DSQ it waits in runs
 * it first. Don't preempt that CPU for it: KVM yields millions of times per
 * second under lock contention, and preempting for every yield takes the
 * host CPUs away from whatever vCPU, maybe the lock holder, runs there.
 */
bool BPF_STRUCT_OPS(pvhost_yield, struct task_struct *from, struct task_struct *to)
{
	struct scx_dispatch_q *dsq;
	u64 dsq_id;

	from->scx.slice = 0;
	if (!to)
		return false;
	dsq = to->scx.dsq;
	if (!dsq)
		return false;
	dsq_id = BPF_CORE_READ(dsq, id);
	/* Waiting for its guest's turn: it goes first when there is one */
	if ((dsq_id >> 32) == 1 && (u32)dsq_id < PV_MAX_GUESTS) {
		guest_yield_pid[(u32)dsq_id] = to->pid;
		__sync_fetch_and_add(&nr_yields, 1);
		return true;
	}
	if (dsq_id >= nr_cpu_ids || dsq_id >= PV_MAX_CPUS)
		return false;
	yield_pid[CPU_IDX(dsq_id)] = to->pid;
	scx_bpf_kick_cpu(dsq_id, SCX_KICK_IDLE);
	__sync_fetch_and_add(&nr_yields, 1);
	return true;
}

/* A vCPU thread woke up: it waits for a host CPU from now on */
void BPF_STRUCT_OPS(pvhost_runnable, struct task_struct *p, u64 enq_flags)
{
	struct vcpu_id *id = vcpu_of(p);

	if (id) {
		*wait_at(id) = scx_bpf_now();
		*runnable_flag(id) = 1;
	}
}

void BPF_STRUCT_OPS(pvhost_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct vcpu_id *id = vcpu_of(p);

	if (id)
		*runnable_flag(id) = 0;
}

void BPF_STRUCT_OPS(pvhost_running, struct task_struct *p)
{
	struct bpf_cpumask *borrowed;
	struct pv_host_vcpu __arena *hv;
	struct vcpu_id *id;
	u64 now, since;
	u32 g, cap;
	s32 cpu;

	pv_running(p);

	id = vcpu_of(p);
	if (!id)
		return;
	g = id->guest % PV_MAX_GUESTS;
	cap = READ_ONCE(guest_cap[g]);
	/* Over the cap: a borrower, see dispatch_borrow() */
	if (__sync_fetch_and_add(&guest_running[g], 1) >= cap && cap) {
		cpu = scx_bpf_task_cpu(p);
		borrowed = borrowed_mask;
		if (borrowed && !bpf_cpumask_test_and_set_cpu(cpu, borrowed)) {
			__sync_fetch_and_add(&nr_borrowed, 1);
			__sync_fetch_and_add(&nr_borrows, 1);
		}
	}
	hv = &shm(id->guest)->hvcpu[id->vcpu];
	/* Before the vCPU resumes, so it sees all of it */
	since = *wait_at(id);
	now = scx_bpf_now();
	if (since && time_before(since, now))
		PV_WRITE(hv->steal_ns, hv->steal_ns + now - since);
	*wait_at(id) = 0;
	PV_WRITE(hv->preempted, 0);
}

void BPF_STRUCT_OPS(pvhost_stopping, struct task_struct *p, bool runnable)
{
	struct bpf_cpumask *borrowed = borrowed_mask;
	struct vcpu_id *id;
	s32 cpu;

	pv_stopping(p);

	cpu = scx_bpf_task_cpu(p);
	id = vcpu_of(p);
	if (borrowed && bpf_cpumask_test_and_clear_cpu(cpu, borrowed))
		__sync_fetch_and_sub(&nr_borrowed, 1);
	if (id && READ_ONCE(guest_running[id->guest % PV_MAX_GUESTS]))
		__sync_fetch_and_sub(&guest_running[id->guest % PV_MAX_GUESTS], 1);
	/* Still runnable: the vCPU thread was preempted, not halted */
	if (id && runnable) {
		struct pv_host_vcpu __arena *hv = &shm(id->guest)->hvcpu[id->vcpu];

		PV_WRITE(hv->preempted, 1);
		hv->nr_preempted++;
		*wait_at(id) = scx_bpf_now();
	}
}

void BPF_STRUCT_OPS(pvhost_enable, struct task_struct *p)
{
	pv_enable(p);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(pvhost_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	return pv_init_task(p);
}

static u32 count_idle_cpus(void)
{
	const struct cpumask *idle = scx_bpf_get_idle_cpumask();
	u32 i, nr = 0;

	if (!nr_pool_cpus) {
		nr = bpf_cpumask_weight(idle);
	} else {
		bpf_for(i, 0, nr_pool_cpus) {
			if (i >= PV_MAX_CPUS)
				break;
			nr += bpf_cpumask_test_cpu(pool_cpus[i], idle);
		}
	}
	scx_bpf_put_idle_cpumask(idle);
	return nr;
}

/*
 * Divide nr_pcpus host CPUs between the ready guests by max-min fairness:
 * hand out equal shares, capped at what each guest wants, and split again
 * what is left among the guests that want more. CPUs that don't split evenly
 * go one each to some of the guests, a different few every ROTATE_NS, so
 * that over time every guest gets the same: with 6 guests on 8 CPUs, the
 * same 2 guests would otherwise always get 2 vCPUs and the others 1.
 */
#define ROTATE_NS	(1000 * 1000 * 1000ULL)

static void update_targets(void)
{
	u32 want[PV_MAX_GUESTS], alloc[PV_MAX_GUESTS];
	u32 g, v, round, total = 0, left = nr_pcpus, active = 0;
	u32 nr_idle = count_idle_cpus();
	struct pv_shared __arena *s;
	u64 now = scx_bpf_now(), seq;

	bpf_for(g, 0, PV_MAX_GUESTS) {
		u32 nr_vcpus, demand;

		want[g] = 0;
		alloc[g] = 0;
		if (!slot_used(g))
			continue;
		s = shm(g);
		seq = PV_READ(s->guest.seq);
		if (seq != guest_seq[g]) {
			guest_seq[g] = seq;
			guest_seen_at[g] = now;
		}
		/* Until its vCPU threads are found, it can't be divided anything */
		if (!READ_ONCE(slot_vcpus[g]))
			continue;
		/*
		 * Without its scheduler, a guest doesn't follow a target. It still
		 * counts, by its runnable vCPU threads, so that the others aren't
		 * asked to fold onto all the host CPUs and leave it the rest.
		 */
		if (!guest_alive(g)) {
			if (!vm_fair)
				continue;
			bpf_for(v, 0, PV_MAX_VCPUS)
				want[g] += vcpu_runnable[(g * PV_MAX_VCPUS + v) &
							 (PV_MAX_GUESTS * PV_MAX_VCPUS - 1)];
			total += want[g];
			active += !!want[g];
			continue;
		}
		/* Don't trust the guest to be as large as it says */
		nr_vcpus = PV_READ(s->guest.nr_vcpus);
		if (nr_vcpus > READ_ONCE(slot_vcpus[g]))
			nr_vcpus = READ_ONCE(slot_vcpus[g]);
		/* Round up, a partly busy vCPU still needs a host CPU */
		demand = (PV_READ(s->guest.demand) + PV_DEMAND_ONE - 1) >> PV_DEMAND_SHIFT;
		want[g] = demand < 1 ? 1 : demand > nr_vcpus ? nr_vcpus : demand;
		total += want[g];
		active++;
	}

	bpf_for(round, 0, PV_MAX_GUESTS) {
		u32 unsat = 0, share, extra, rot, i = 0;

		if (total <= nr_pcpus)
			break;
		bpf_for(g, 0, PV_MAX_GUESTS)
			if (alloc[g] < want[g])
				unsat++;
		if (!unsat || !left)
			break;
		share = left / unsat;
		extra = left % unsat;
		rot = now / ROTATE_NS % unsat;
		bpf_for(g, 0, PV_MAX_GUESTS) {
			u32 give = want[g] - alloc[g], mine = share;

			if (!give)
				continue;
			/* The guests that get one more this time */
			if ((i++ + rot) % unsat < extra)
				mine++;
			if (give > mine)
				give = mine;
			if (give > left)
				give = left;
			alloc[g] += give;
			left -= give;
		}
	}

	bpf_for(g, 0, PV_MAX_GUESTS) {
		if (!slot_used(g))
			continue;
		s = shm(g);
		if (PV_READ(s->host.epoch) != slot_epoch[g]) {
			PV_WRITE(s->host.guest_id, g);
			PV_WRITE(s->host.version, PV_VERSION);
			PV_WRITE(s->host.epoch, slot_epoch[g]);
			PV_WRITE(s->host.magic, PV_MAGIC);
		}
		PV_WRITE(s->host.nr_pcpus, nr_pcpus);
		PV_WRITE(s->host.nr_guests, active);
		PV_WRITE(s->host.nr_idle_pcpus, nr_idle);
		/*
		 * No contention, or a guest that doesn't count: no limit.
		 * Otherwise at least one vCPU.
		 */
		PV_WRITE(s->host.target_vcpus,
			   total <= nr_pcpus || !want[g] ? 0 : alloc[g] ?: 1);
		/* A guest that doesn't follow its target is held to it */
		WRITE_ONCE(guest_cap[g], !vm_fair || guest_alive(g) ||
			   total <= nr_pcpus || !want[g] ? 0 : alloc[g] ?: 1);
		PV_WRITE(s->host.seq, s->host.seq + 1);
	}
}

static int pv_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	update_targets();
	if (vm_fair) {
		bpf_rcu_read_lock();
		kick_capped();
		bpf_rcu_read_unlock();
	}
	bpf_timer_start(timer, TIMER_NS, 0);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(pvhost_init)
{
	struct bpf_cpumask *mask;
	struct bpf_timer *timer;
	u32 key = 0, g;
	s32 ret;

	ret = pv_init();
	if (ret)
		return ret;
	mask = bpf_cpumask_create();
	if (!mask)
		return -ENOMEM;
	mask = bpf_kptr_xchg(&borrowed_mask, mask);
	if (mask)
		bpf_cpumask_release(mask);
	bpf_for(g, 0, PV_MAX_GUESTS) {
		ret = scx_bpf_create_dsq(GUEST_DSQ(g), -1);
		if (ret)
			return ret;
	}

	timer = bpf_map_lookup_elem(&pv_timer, &key);
	if (!timer)
		return -ESRCH;
	bpf_timer_init(timer, &pv_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, pv_timerfn);
	return bpf_timer_start(timer, TIMER_NS, 0);
}

void BPF_STRUCT_OPS(pvhost_exit, struct scx_exit_info *ei)
{
	u32 g;

	/* Let the guests use all their vCPUs again */
	bpf_for(g, 0, PV_MAX_GUESTS)
		if (slot_used(g))
			PV_WRITE(shm(g)->host.target_vcpus, 0);
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(pvhost_ops,
	       .select_cpu		= (void *)pvhost_select_cpu,
	       .enqueue			= (void *)pvhost_enqueue,
	       .dispatch		= (void *)pvhost_dispatch,
	       .yield			= (void *)pvhost_yield,
	       .runnable		= (void *)pvhost_runnable,
	       .quiescent		= (void *)pvhost_quiescent,
	       .running			= (void *)pvhost_running,
	       .stopping		= (void *)pvhost_stopping,
	       .enable			= (void *)pvhost_enable,
	       .init_task		= (void *)pvhost_init_task,
	       .init			= (void *)pvhost_init,
	       .exit			= (void *)pvhost_exit,
	       .flags			= PV_OPS_FLAGS,
	       .name			= "pvhost");
