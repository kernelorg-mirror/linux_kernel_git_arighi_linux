// SPDX-License-Identifier: GPL-2.0
/*
 * Verify initial preferred-node delivery and subsequent NUMA notifications.
 *
 * Copyright (c) 2026 NVIDIA Corporation.
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct task_ctx {
	bool enabled;
	bool notified;
	s32 nid;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

u64 nr_enabled;
u64 nr_initial;
u64 nr_updates;
/* Notifications with and without a preferred node. */
u64 nr_with_nid;
u64 nr_without_nid;

s32 BPF_STRUCT_OPS_SLEEPABLE(numa_nid_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	if (!bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE))
		return -ENOMEM;
	return 0;
}

static struct task_ctx *task_ctx(struct task_struct *p)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);

	if (!tctx)
		scx_bpf_error("task %d has no task storage", p->pid);
	return tctx;
}

void BPF_STRUCT_OPS(numa_nid_enable, struct task_struct *p)
{
	struct task_ctx *tctx = task_ctx(p);

	if (!tctx)
		return;
	tctx->enabled = true;
	tctx->notified = false;
	__sync_fetch_and_add(&nr_enabled, 1);
}

void BPF_STRUCT_OPS(numa_nid_set_numa_node, struct task_struct *p, s32 nid)
{
	struct task_ctx *tctx = task_ctx(p);
	s32 stored_nid = NUMA_NO_NODE;

	if (!tctx)
		return;
	if (!tctx->enabled) {
		scx_bpf_error("task %d notified before enable or after disable", p->pid);
		return;
	}
	if (bpf_core_field_exists(p->numa_preferred_nid))
		stored_nid = p->numa_preferred_nid;
	if (nid != stored_nid) {
		scx_bpf_error("task %d reported node %d, stored node %d",
			      p->pid, nid, stored_nid);
		return;
	}
	if (tctx->notified) {
		if (nid == tctx->nid) {
			scx_bpf_error("task %d repeated node %d", p->pid, nid);
			return;
		}
		__sync_fetch_and_add(&nr_updates, 1);
	} else {
		__sync_fetch_and_add(&nr_initial, 1);
	}
	tctx->notified = true;
	tctx->nid = nid;

	if (nid == NUMA_NO_NODE) {
		__sync_fetch_and_add(&nr_without_nid, 1);
		return;
	}

	if (nid < 0 || nid >= scx_bpf_nr_node_ids()) {
		scx_bpf_error("task %d reported node %d, kernel has %d node ids",
			      p->pid, nid, scx_bpf_nr_node_ids());
		return;
	}

	__sync_fetch_and_add(&nr_with_nid, 1);
}

void BPF_STRUCT_OPS(numa_nid_running, struct task_struct *p)
{
	struct task_ctx *tctx = task_ctx(p);

	if (tctx && !tctx->notified)
		scx_bpf_error("task %d ran before initial node notification", p->pid);
}

void BPF_STRUCT_OPS(numa_nid_disable, struct task_struct *p)
{
	struct task_ctx *tctx = task_ctx(p);

	if (!tctx)
		return;
	if (!tctx->notified)
		scx_bpf_error("task %d disabled without initial node notification", p->pid);
	tctx->enabled = false;
}

void BPF_STRUCT_OPS(numa_nid_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops numa_nid_ops = {
	.init_task			= (void *)numa_nid_init_task,
	.enable				= (void *)numa_nid_enable,
	.set_numa_node			= (void *)numa_nid_set_numa_node,
	.running			= (void *)numa_nid_running,
	.disable			= (void *)numa_nid_disable,
	.exit				= (void *)numa_nid_exit,
	.name				= "numa_nid",
};
