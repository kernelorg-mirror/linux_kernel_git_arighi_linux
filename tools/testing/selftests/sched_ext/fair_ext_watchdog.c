// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */

#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "fair_ext_watchdog.bpf.skel.h"
#include "scx_test.h"

#define WATCHDOG_WORKERS 8

struct fair_ext_watchdog_ctx {
	struct fair_ext_watchdog *skel;
	struct bpf_link *link;
	pid_t workers[WATCHDOG_WORKERS];
};

static enum scx_test_status setup(void **arg)
{
	struct fair_ext_watchdog_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));
	SCX_FAIL_IF(!ctx, "Failed to allocate context");
	for (int i = 0; i < WATCHDOG_WORKERS; i++)
		ctx->workers[i] = -1;
	*arg = ctx;

	return SCX_TEST_PASS;
}

static void cleanup(void *arg)
{
	struct fair_ext_watchdog_ctx *ctx = arg;
	int status;

	for (int i = 0; i < WATCHDOG_WORKERS; i++) {
		if (ctx->workers[i] <= 0)
			continue;
		kill(ctx->workers[i], SIGKILL);
		waitpid(ctx->workers[i], &status, 0);
	}
	bpf_link__destroy(ctx->link);
	fair_ext_watchdog__destroy(ctx->skel);
	free(ctx);
}

static int first_cpu(const cpu_set_t *mask)
{
	int cpu;

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, mask))
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

static void run_busy(int cpu)
{
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask))
		_exit(1);

	for (;;)
		asm volatile("" ::: "memory");
}

static enum scx_test_status test_watchdog(void *arg)
{
	struct fair_ext_watchdog_ctx *ctx = arg;
	cpu_set_t allowed;
	char state[16];
	__u64 calls;
	int cpu, status;
	bool disabled = false;

	SCX_EQ(0, sched_getaffinity(0, sizeof(allowed), &allowed));
	cpu = first_cpu(&allowed);
	SCX_GE(cpu, 0);

	ctx->skel = fair_ext_watchdog__open();
	SCX_FAIL_IF(!ctx->skel, "Failed to open BPF skeleton");
	ctx->skel->struct_ops.ext_ops->timeout_ms = 1;
	SCX_EQ(0, fair_ext_watchdog__load(ctx->skel));

	ctx->link = bpf_map__attach_struct_ops(ctx->skel->maps.ext_ops);
	SCX_FAIL_IF(!ctx->link, "Failed to attach struct_ops");
	SCX_EQ(0, read_fair_ext_state(state, sizeof(state)));
	SCX_FAIL_IF(strcmp("enabled", state), "Unexpected state: %s", state);

	for (int i = 0; i < WATCHDOG_WORKERS; i++) {
		ctx->workers[i] = fork();
		SCX_GE(ctx->workers[i], 0);
		if (!ctx->workers[i])
			run_busy(cpu);
	}

	/* Eight workers on one CPU must leave one runnable beyond one tick. */
	usleep(500000);
	for (int i = 0; i < 50; i++) {
		pid_t probe;

		calls = ctx->skel->bss->nr_calls;
		probe = fork();
		SCX_GE(probe, 0);
		if (!probe)
			_exit(0);
		SCX_EQ(probe, waitpid(probe, &status, 0));
		SCX_ASSERT(WIFEXITED(status));
		if (calls == ctx->skel->bss->nr_calls) {
			disabled = true;
			break;
		}
		usleep(20000);
	}

	SCX_ASSERT(disabled);
	SCX_EQ(0, read_fair_ext_state(state, sizeof(state)));
	SCX_FAIL_IF(strcmp("faulted", state), "Unexpected state: %s", state);
	calls = ctx->skel->bss->nr_calls;
	usleep(50000);
	SCX_EQ(calls, ctx->skel->bss->nr_calls);

	bpf_link__destroy(ctx->link);
	ctx->link = NULL;
	SCX_EQ(0, read_fair_ext_state(state, sizeof(state)));
	SCX_FAIL_IF(strcmp("disabled", state), "Unexpected state: %s", state);

	return SCX_TEST_PASS;
}

struct scx_test fair_ext_watchdog = {
	.name = "fair_ext.watchdog",
	.description = "Verify fair sched_ext watchdog enforcement",
	.setup = setup,
	.run = test_watchdog,
	.cleanup = cleanup,
};

REGISTER_SCX_TEST(&fair_ext_watchdog)
