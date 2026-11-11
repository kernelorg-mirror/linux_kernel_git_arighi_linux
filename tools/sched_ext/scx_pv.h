/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared memory protocol between scx_pvhost and scx_pvguest.
 *
 * The host scheduler watches a directory, /run/scx-pv by default. A VM whose
 * virtio-pmem or NVDIMM device is backed by a file there (memory-backend-file,
 * share=on, on tmpfs or hugetlbfs) gets registered: the host maps the file
 * and the guest turns the device into /dev/dax0.0 (devdax mode, memmap in
 * guest RAM). The host imports the file into its arena with
 * bpf_arena_import_memfd(), the guest imports /dev/dax0.0 into its own with
 * bpf_arena_import_dax(), so the host and guest schedulers read and write
 * struct pv_shared with plain loads and stores.
 *
 * Every field has a single writer. Host-written and guest-written fields
 * live in separate cachelines. Nothing in here is a pointer: the arenas of
 * the two sides live at different addresses.
 *
 * Copyright (c) 2026 NVIDIA Corporation.
 */
#ifndef __SCX_PV_H
#define __SCX_PV_H

#ifndef __bpf__
#include <linux/types.h>
#endif

/*
 * Single-copy accesses to the shared pages, the other side may change them at
 * any time. Every field is an independent snapshot, nothing relies on the
 * order in which two of them become visible. In BPF programs, typeof() keeps
 * the arena address space.
 */
#define PV_READ(x)	(*(volatile typeof(x) *)&(x))
#define PV_WRITE(x, v)	(*(volatile typeof(x) *)&(x) = (v))

#define PV_MEMFD_SIZE		(16ULL << 20)	/* backing file, minimum for a devdax namespace */
#define PV_DAX_OFF		(2ULL << 20)	/* devdax data offset in the backing file */
#define PV_PAGES		4		/* imported per guest */
/*
 * First arena page of the shared pages. Arena page 0 stays unused: its address
 * is NULL to the import kfuncs when the arena starts on a 4GB boundary.
 */
#define PV_ARENA_FIRST		1
#define PV_MAX_GUESTS		16
#define PV_MAX_VCPUS		64

#define PV_MAGIC		0x31767078637300ULL	/* "\0scxpv1" */
#define PV_VERSION		2
#define PV_GUEST_READY		0x59444145u		/* "EADY" */

/* Guest demand is a running average of runnable tasks, in 1/PV_DEMAND_ONE units */
#define PV_DEMAND_SHIFT		8
#define PV_DEMAND_ONE		(1u << PV_DEMAND_SHIFT)

#define PV_CACHELINE		64

/* Topology limits of the base policy, see scx_pvsched.bpf.h */
#define PV_MAX_CPUS		512
#define PV_MAX_LLCS		32
#define PV_MAX_TIERS		4

enum pv_vcpu_state {
	PV_VCPU_IDLE,		/* idle, may be used */
	PV_VCPU_RUNNING,	/* running a task */
	PV_VCPU_FOLDED,		/* idle and not used, beyond target_vcpus */
};

/*
 * Heartbeats: the host bumps host.seq every millisecond and the guest
 * guest.seq every few. Either side ignores the other when its seq stops
 * moving: a host scheduler restarted or a guest scheduler gone. The host
 * writes a new random epoch whenever it (re)registers the guest.
 */
#define PV_HOST_STALE_NS	(50 * 1000 * 1000ULL)
#define PV_GUEST_STALE_NS	(100 * 1000 * 1000ULL)

/* Written by the host */
struct pv_host_info {
	__u64 magic;
	__u32 version;		/* PV_VERSION */
	__u32 guest_id;		/* slot of the guest in the host's arena */
	__u64 epoch;		/* changes when the host (re)registers the guest */
	__u32 target_vcpus;	/* vCPUs the guest should use, 0 means all */
	__u32 nr_pcpus;		/* host CPUs shared by all guests */
	__u32 nr_guests;	/* guests competing for them */
	__u32 nr_idle_pcpus;	/* host CPUs idle right now */
	__u64 seq;		/* heartbeat, bumped at every update */
} __attribute__((aligned(PV_CACHELINE)));

/* Written by the guest */
struct pv_guest_info {
	__u32 ready;		/* PV_GUEST_READY while scx_pvguest runs */
	__u32 nr_vcpus;
	__u32 demand;		/* runnable tasks, PV_DEMAND_ONE == one task */
	__u32 nr_folded;	/* vCPUs currently folded */
	__u64 seq;		/* heartbeat, bumped at every update */
} __attribute__((aligned(PV_CACHELINE)));

/* Written by the guest, one per vCPU */
struct pv_guest_vcpu {
	__u32 state;		/* enum pv_vcpu_state */
} __attribute__((aligned(PV_CACHELINE)));

/* Written by the host, one per vCPU */
struct pv_host_vcpu {
	__u32 preempted;	/* vCPU thread runnable but not running on the host */
	__u64 nr_preempted;	/* times the host preempted the vCPU thread */
	/*
	 * Time the vCPU thread waited for a host CPU so far, in ns: KVM's
	 * steal time, updated before the vCPU runs again. The guest doesn't
	 * charge it to its tasks, whatever its kernel's config.
	 */
	__u64 steal_ns;
} __attribute__((aligned(PV_CACHELINE)));

struct pv_shared {
	struct pv_host_info host;
	struct pv_guest_info guest;
	struct pv_guest_vcpu gvcpu[PV_MAX_VCPUS];
	struct pv_host_vcpu hvcpu[PV_MAX_VCPUS];
};

_Static_assert(sizeof(struct pv_shared) <= PV_PAGES * 4096,
	       "struct pv_shared doesn't fit in the imported pages");

#endif /* __SCX_PV_H */
