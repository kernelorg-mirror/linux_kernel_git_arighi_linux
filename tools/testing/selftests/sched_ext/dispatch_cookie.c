/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Test scx_bpf_dsq_insert_begin() and scx_bpf_dsq_insert_commit().
 *
 * Copyright (C) 2026 Ching-Chun (Jim) Huang <jserv@ccns.ncku.edu.tw>
 * Copyright (C) 2026 Cheng-Yang Chou <yphbchou0911@gmail.com>
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <errno.h>
#include <sched.h>
#include <scx/common.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "dispatch_cookie.bpf.skel.h"
#include "scx_test.h"

#define NUM_CHILDREN	32
#define NUM_FLIP_ITERS	100

struct dispatch_cookie_ctx {
	struct dispatch_cookie	*skel;
	struct bpf_link		*link;
};

static enum scx_test_status setup(void **ctx)
{
	struct dispatch_cookie_ctx *tctx;

	if (!__COMPAT_has_ksym("scx_bpf_dsq_insert_begin")) {
		fprintf(stderr, "SKIP: dispatch transaction API not supported\n");
		return SCX_TEST_SKIP;
	}

	tctx = malloc(sizeof(*tctx));
	SCX_FAIL_IF(!tctx, "Failed to allocate test context");
	tctx->skel = NULL;
	tctx->link = NULL;
	*ctx = tctx;

	tctx->skel = dispatch_cookie__open();
	SCX_FAIL_IF(!tctx->skel, "Failed to open skel");

	SCX_ENUM_INIT(tctx->skel);
	SCX_FAIL_IF(dispatch_cookie__load(tctx->skel), "Failed to load skel");

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct dispatch_cookie_ctx *tctx = ctx;
	cpu_set_t cpuset_one, cpuset_all;
	pid_t pids[NUM_CHILDREN];
	int i, j, nforked = 0, status, first_cpu;

	tctx->link = bpf_map__attach_struct_ops(tctx->skel->maps.dispatch_cookie_ops);
	SCX_FAIL_IF(!tctx->link, "Failed to attach scheduler");

	SCX_FAIL_IF(sched_getaffinity(0, sizeof(cpuset_all), &cpuset_all),
		    "Failed to get CPU affinity (%d)", errno);

	first_cpu = -1;
	for (i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &cpuset_all)) {
			first_cpu = i;
			break;
		}
	}
	SCX_FAIL_IF(first_cpu < 0, "No online CPUs found");

	CPU_ZERO(&cpuset_one);
	CPU_SET(first_cpu, &cpuset_one);

	for (i = 0; i < NUM_CHILDREN; i++) {
		pids[i] = fork();
		if (pids[i] == 0) {
			while (1)
				sched_yield();
		}
		if (pids[i] > 0)
			nforked++;
	}

	/*
	 * Flip affinity to trigger dequeue/re-enqueue, which increments qseq
	 * and makes previously captured tokens stale.
	 */
	for (i = 0; i < NUM_FLIP_ITERS; i++) {
		for (j = 0; j < NUM_CHILDREN; j++) {
			if (pids[j] <= 0)
				continue;
			sched_setaffinity(pids[j], sizeof(cpuset_one), &cpuset_one);
			sched_setaffinity(pids[j], sizeof(cpuset_all), &cpuset_all);
		}
		usleep(1000);
	}

	for (i = 0; i < NUM_CHILDREN; i++) {
		if (pids[i] <= 0)
			continue;
		kill(pids[i], SIGKILL);
		waitpid(pids[i], &status, 0);
	}

	SCX_GT(nforked, 0);
	SCX_GT(tctx->skel->bss->nr_tx_dispatched, 0);
	SCX_GT(tctx->skel->bss->nr_tx_stale, 0);

	return SCX_TEST_PASS;
}

static void cleanup(void *ctx)
{
	struct dispatch_cookie_ctx *tctx = ctx;

	if (!tctx)
		return;
	if (tctx->link)
		bpf_link__destroy(tctx->link);
	dispatch_cookie__destroy(tctx->skel);
	free(tctx);
}

struct scx_test dispatch_cookie = {
	.name		= "dispatch_cookie",
	.description	= "Verify scx_bpf_dsq_insert_begin() and "
			  "scx_bpf_dsq_insert_commit() dispatch tasks correctly",
	.setup		= setup,
	.run		= run,
	.cleanup	= cleanup,
};
REGISTER_SCX_TEST(&dispatch_cookie)
