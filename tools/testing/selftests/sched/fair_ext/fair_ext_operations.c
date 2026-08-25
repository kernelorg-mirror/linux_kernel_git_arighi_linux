// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */

#define _GNU_SOURCE
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "fair_ext_operations.bpf.skel.h"
#include "fair_ext_test.h"

#define NS_PER_SEC 1000000000L
#define NS_PER_MSEC 1000000L

struct fair_ext_ctx {
	struct fair_ext_operations *skel;
	struct bpf_link *link;
	int wake_pipe[2];
	int result_pipe[2];
	pid_t child;
};

static enum fair_ext_test_status setup(void **arg)
{
	struct fair_ext_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));
	FAIR_EXT_FAIL_IF(!ctx, "Failed to allocate context");
	ctx->wake_pipe[0] = -1;
	ctx->wake_pipe[1] = -1;
	ctx->result_pipe[0] = -1;
	ctx->result_pipe[1] = -1;
	ctx->child = -1;
	*arg = ctx;

	return FAIR_EXT_TEST_PASS;
}

static void cleanup(void *arg)
{
	struct fair_ext_ctx *ctx = arg;
	int status;

	if (ctx->wake_pipe[1] >= 0)
		close(ctx->wake_pipe[1]);
	if (ctx->result_pipe[0] >= 0)
		close(ctx->result_pipe[0]);
	if (ctx->wake_pipe[0] >= 0)
		close(ctx->wake_pipe[0]);
	if (ctx->result_pipe[1] >= 0)
		close(ctx->result_pipe[1]);
	if (ctx->child > 0) {
		kill(ctx->child, SIGCONT);
		if (waitpid(ctx->child, &status, 0) < 0) {
			kill(ctx->child, SIGKILL);
			waitpid(ctx->child, &status, 0);
		}
	}
	bpf_link__destroy(ctx->link);
	fair_ext_operations__destroy(ctx->skel);
	free(ctx);
}

#define FAIR_EXT_NE(_x, _y) FAIR_EXT_FAIL_IF((_x) == (_y), "Expected %s != %s", #_x, #_y)

static int first_cpu(const cpu_set_t *mask, int skip)
{
	int cpu;

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, mask) || cpu == skip)
			continue;
		return cpu;
	}
	return -1;
}

static int first_cpu_except(const cpu_set_t *mask, int skip1, int skip2)
{
	int cpu;

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, mask) || cpu == skip1 || cpu == skip2)
			continue;
		return cpu;
	}
	return -1;
}

static int read_fair_ext_state(char *state, size_t size)
{
	FILE *file;

	file = fopen("/sys/kernel/fair_ext/state", "r");
	if (!file)
		return -1;
	if (!fgets(state, size, file)) {
		fclose(file);
		return -1;
	}
	fclose(file);
	state[strcspn(state, "\n")] = '\0';
	return 0;
}

static int child_fn(int wake_fd, int result_fd)
{
	struct timespec start, now;
	char byte;
	int cpu;

	for (;;) {
		raise(SIGSTOP);
		if (read(wake_fd, &byte, sizeof(byte)) != sizeof(byte))
			break;

		/* Consume enough runtime to exercise periodic balancing. */
		if (clock_gettime(CLOCK_MONOTONIC, &start))
			return 1;
		do {
			if (clock_gettime(CLOCK_MONOTONIC, &now))
				return 1;
		} while ((now.tv_sec - start.tv_sec) * NS_PER_SEC +
			 now.tv_nsec - start.tv_nsec < 20 * NS_PER_MSEC);

		cpu = sched_getcpu();
		if (write(result_fd, &cpu, sizeof(cpu)) != sizeof(cpu))
			return 1;
	}
	return 0;
}

static int wake_child(pid_t child, int wake_fd, int result_fd)
{
	char byte = 0;
	int status;
	int cpu = -1;

	if (waitpid(child, &status, WUNTRACED) != child || !WIFSTOPPED(status))
		return -1;
	if (write(wake_fd, &byte, sizeof(byte)) != sizeof(byte))
		return -1;
	if (kill(child, SIGCONT))
		return -1;
	if (read(result_fd, &cpu, sizeof(cpu)) != sizeof(cpu))
		return -1;
	return cpu;
}

static enum fair_ext_test_status test_operations(void *arg)
{
	LIBBPF_OPTS(bpf_test_run_opts, run_opts);
	struct fair_ext_ctx *ctx = arg;
	cpu_set_t allowed, child_mask;
	char state[16];
	long nr_online;
	int cpu0, cpu1, cpu2, err, observed, prog_fd;
	__u64 calls, count, empty_count;

	FAIR_EXT_EQ(0, sched_getaffinity(0, sizeof(allowed), &allowed));
	cpu0 = first_cpu(&allowed, -1);
	cpu1 = first_cpu(&allowed, cpu0);
	if (cpu1 < 0)
		return FAIR_EXT_TEST_SKIP;
	cpu2 = first_cpu_except(&allowed, cpu0, cpu1);

	ctx->skel = fair_ext_operations__open();
	FAIR_EXT_NE(NULL, ctx->skel);
	ctx->skel->data->preferred_cpu = cpu0;
	FAIR_EXT_EQ(0, fair_ext_operations__load(ctx->skel));
	prog_fd = bpf_program__fd(ctx->skel->progs.init_preferred_mask);
	err = bpf_prog_test_run_opts(prog_fd, &run_opts);
	FAIR_EXT_EQ(0, err);
	FAIR_EXT_EQ(0, run_opts.retval);

	ctx->link = bpf_map__attach_struct_ops(ctx->skel->maps.ext_ops);
	FAIR_EXT_NE(NULL, ctx->link);
	nr_online = sysconf(_SC_NPROCESSORS_ONLN);
	FAIR_EXT_GT(nr_online, 0);
	FAIR_EXT_GE(ctx->skel->bss->nr_update_idle, nr_online);
	FAIR_EXT_GT(ctx->skel->bss->nr_idle_exit, 0);
	FAIR_EXT_EQ(0, read_fair_ext_state(state, sizeof(state)));
	FAIR_EXT_FAIL_IF(strcmp("enabled", state), "Unexpected state: %s", state);

	FAIR_EXT_EQ(0, pipe(ctx->wake_pipe));
	FAIR_EXT_EQ(0, pipe(ctx->result_pipe));

	ctx->child = fork();
	FAIR_EXT_GE(ctx->child, 0);
	if (!ctx->child) {
		close(ctx->wake_pipe[1]);
		close(ctx->result_pipe[0]);
		_exit(child_fn(ctx->wake_pipe[0], ctx->result_pipe[1]));
	}

	close(ctx->wake_pipe[0]);
	ctx->wake_pipe[0] = -1;
	close(ctx->result_pipe[1]);
	ctx->result_pipe[1] = -1;

	CPU_ZERO(&child_mask);
	CPU_SET(cpu0, &child_mask);
	CPU_SET(cpu1, &child_mask);
	err = sched_setaffinity(ctx->child, sizeof(child_mask), &child_mask);
	FAIR_EXT_EQ(0, err);
	FAIR_EXT_EQ(SCHED_OTHER, sched_getscheduler(ctx->child));

	ctx->skel->data->target_pid = ctx->child;
	ctx->skel->data->target_cpu = cpu1;
	count = ctx->skel->bss->nr_overrides;
	observed = wake_child(ctx->child, ctx->wake_pipe[1], ctx->result_pipe[0]);
	FAIR_EXT_GT(ctx->skel->bss->nr_overrides, count);
	FAIR_EXT_EQ(cpu1, observed);

	/* Prefer an idle CPU from a BPF-provided singleton mask. */
	ctx->skel->bss->use_fair_mask = true;
	count = ctx->skel->bss->nr_fair_mask;
	observed = wake_child(ctx->child, ctx->wake_pipe[1], ctx->result_pipe[0]);
	FAIR_EXT_GT(ctx->skel->bss->nr_fair_mask, count);
	FAIR_EXT_GT(ctx->skel->bss->nr_cpu_idle, 0);
	FAIR_EXT_ASSERT(observed == cpu0 || observed == cpu1);
	ctx->skel->bss->use_fair_mask = false;

	/* An empty preferred/affinity intersection must fail open to fair. */
	if (cpu2 >= 0) {
		ctx->skel->data->preferred_cpu = cpu2;
		prog_fd = bpf_program__fd(ctx->skel->progs.init_preferred_mask);
		err = bpf_prog_test_run_opts(prog_fd, &run_opts);
		FAIR_EXT_EQ(0, err);
		FAIR_EXT_EQ(0, run_opts.retval);

		ctx->skel->bss->use_fair_mask = true;
		count = ctx->skel->bss->nr_fair_mask;
		empty_count = ctx->skel->bss->nr_fair_mask_empty;
		observed = wake_child(ctx->child, ctx->wake_pipe[1], ctx->result_pipe[0]);
		FAIR_EXT_GT(ctx->skel->bss->nr_fair_mask, count);
		FAIR_EXT_GT(ctx->skel->bss->nr_fair_mask_empty, empty_count);
		FAIR_EXT_ASSERT(observed == cpu0 || observed == cpu1);
		ctx->skel->bss->use_fair_mask = false;
	}

	/* An invalid result must fail open to fair placement. */
	ctx->skel->data->target_cpu = INT_MAX;
	count = ctx->skel->bss->nr_overrides;
	observed = wake_child(ctx->child, ctx->wake_pipe[1], ctx->result_pipe[0]);
	FAIR_EXT_GT(ctx->skel->bss->nr_overrides, count);
	FAIR_EXT_ASSERT(observed == cpu0 || observed == cpu1);

	/* A negative result explicitly requests fair's default selector. */
	ctx->skel->data->target_cpu = -1;
	count = ctx->skel->bss->nr_fallbacks;
	observed = wake_child(ctx->child, ctx->wake_pipe[1], ctx->result_pipe[0]);
	FAIR_EXT_GT(ctx->skel->bss->nr_fallbacks, count);
	FAIR_EXT_ASSERT(observed == cpu0 || observed == cpu1);
	FAIR_EXT_GT(ctx->skel->bss->nr_balance, 0);
	FAIR_EXT_GT(ctx->skel->bss->nr_idle_queries, 0);

	calls = ctx->skel->bss->nr_calls;
	bpf_link__destroy(ctx->link);
	ctx->link = NULL;
	observed = wake_child(ctx->child, ctx->wake_pipe[1], ctx->result_pipe[0]);
	FAIR_EXT_ASSERT(observed == cpu0 || observed == cpu1);
	FAIR_EXT_EQ(calls, ctx->skel->bss->nr_calls);

	return FAIR_EXT_TEST_PASS;
}

struct fair_ext_test fair_ext_operations = {
	.name = "fair_ext.operations",
	.description = "Verify sched_fair_ops callbacks and native fallback",
	.setup = setup,
	.run = test_operations,
	.cleanup = cleanup,
};

REGISTER_FAIR_EXT_TEST(&fair_ext_operations)
