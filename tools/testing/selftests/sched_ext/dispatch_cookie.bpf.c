/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Test scx_bpf_dsq_insert_begin() and scx_bpf_dsq_insert_commit().
 *
 * Exercises both the happy path (fresh token committed successfully) and
 * the stale-token path (stored token reused after the task was dequeued and
 * re-enqueued, incrementing qseq and making the token stale).
 *
 * Copyright (C) 2026 Ching-Chun (Jim) Huang <jserv@ccns.ncku.edu.tw>
 * Copyright (C) 2026 Cheng-Yang Chou <yphbchou0911@gmail.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 8192);
	__type(value, s32);
} queue SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, s32);
	__type(value, u64);
} last_token SEC(".maps");

long nr_tx_dispatched;
long nr_tx_stale;

void BPF_STRUCT_OPS(dispatch_cookie_enqueue, struct task_struct *p,
		    u64 enq_flags)
{
	s32 pid = p->pid;

	if (bpf_map_push_elem(&queue, &pid, 0))
		scx_bpf_error("Failed to enqueue %s[%d]", p->comm, p->pid);
}

void BPF_STRUCT_OPS(dispatch_cookie_dispatch, s32 cpu,
		    struct task_struct *prev)
{
	s32 pid;
	struct task_struct *p;
	u64 *stored, token;

	if (bpf_map_pop_elem(&queue, &pid))
		return;

	p = bpf_task_from_pid(pid);
	if (!p)
		return;

	/*
	 * Tasks pinned to a different CPU (e.g. per-CPU kworkers) cannot be
	 * inserted into this CPU's local DSQ. Skip the transaction path and
	 * fall back to the global DSQ so the scheduler does not abort.
	 */
	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
		bpf_task_release(p);
		return;
	}

	/*
	 * After a successful fresh dispatch, store the token. On the task's
	 * next dispatch (after re-enqueue increments qseq), the stored token
	 * exercises the stale path in finish_dispatch().
	 *
	 * scx_bpf_dsq_insert_commit() always returns %true when the preamble
	 * passes; stale detection fires asynchronously in finish_dispatch()
	 * with no BPF-observable signal. Always pair the commit() call with a
	 * fallback scx_bpf_dsq_insert(): if the token is stale,
	 * finish_dispatch() drops the buffered entry and the fallback
	 * dispatches the task. If the token is still fresh, finish_dispatch()
	 * dispatches it and the fallback's CAS is a no-op.
	 */
	struct scx_bpf_dsq_insert_commit_args commit_args = {
		.dsq_id		= SCX_DSQ_LOCAL,
		.slice		= 0,
		.enq_flags	= 0,
	};

	stored = bpf_map_lookup_elem(&last_token, &pid);
	if (stored) {
		token = *stored;
		bpf_map_delete_elem(&last_token, &pid);
		scx_bpf_dsq_insert_commit(p, &commit_args, token);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		/* counts attempted stale commits, not finish_dispatch() rejections */
		__sync_fetch_and_add(&nr_tx_stale, 1);
	} else {
		token = scx_bpf_dsq_insert_begin(p);
		if (scx_bpf_dsq_insert_commit(p, &commit_args, token)) {
			__sync_fetch_and_add(&nr_tx_dispatched, 1);
			bpf_map_update_elem(&last_token, &pid, &token, BPF_ANY);
		} else {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		}
	}

	bpf_task_release(p);
}

void BPF_STRUCT_OPS(dispatch_cookie_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops dispatch_cookie_ops = {
	.enqueue		= (void *) dispatch_cookie_enqueue,
	.dispatch		= (void *) dispatch_cookie_dispatch,
	.exit			= (void *) dispatch_cookie_exit,
	.name			= "dispatch_cookie",
	.timeout_ms		= 5000U,
};
