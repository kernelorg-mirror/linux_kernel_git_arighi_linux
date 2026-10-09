// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA Corporation.
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <linux/numa.h>
#include <pthread.h>
#include <scx/common.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "numa_nid.bpf.skel.h"
#include "scx_test.h"

#define UPDATE_TIMEOUT		30

#define WORKLOAD_SIZE		(64 << 20)
#define WORKLOAD_THREADS	2
#define WORKLOAD_SECONDS	3
/* Returned by touch_memory() when its buffer can't be allocated. */
#define WORKLOAD_FAILED		((void *)1)

/*
 * Touch a private buffer for a while. The hinting-fault scan skips the pages
 * of a single-threaded process that are already on the node it runs on, so
 * one such thread alone would never take a hinting fault: run two of them.
 */
static void *touch_memory(void *arg)
{
	struct timespec start, now;
	volatile char *buffer;
	size_t offset;

	buffer = malloc(WORKLOAD_SIZE);
	if (!buffer)
		return WORKLOAD_FAILED;

	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		for (offset = 0; offset < WORKLOAD_SIZE; offset += 4096)
			buffer[offset]++;
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while (now.tv_sec - start.tv_sec < WORKLOAD_SECONDS);

	free((void *)buffer);
	return NULL;
}

/*
 * Run touch_memory() in the calling thread and in WORKLOAD_THREADS - 1 new
 * ones. Return false if a thread can't be created or a buffer allocated.
 */
static bool run_workload(void)
{
	pthread_t threads[WORKLOAD_THREADS - 1];
	bool failed = false;
	void *ret;
	int i, nr_threads;

	for (nr_threads = 0; nr_threads < WORKLOAD_THREADS - 1; nr_threads++) {
		if (pthread_create(&threads[nr_threads], NULL, touch_memory, NULL)) {
			failed = true;
			break;
		}
	}
	failed |= touch_memory(NULL) == WORKLOAD_FAILED;
	for (i = 0; i < nr_threads; i++) {
		pthread_join(threads[i], &ret);
		failed |= ret == WORKLOAD_FAILED;
	}
	return !failed;
}

/*
 * The node list is in bitmap list format, e.g. "0-3" or "0,2-3", where a range
 * always spans at least two nodes, so the second node is either the one after
 * the first in a range or the next entry in the list.
 */
static int second_memory_node(void)
{
	FILE *file;
	int first, second = NUMA_NO_NODE;
	char sep;

	file = fopen("/sys/devices/system/node/has_memory", "r");
	if (!file)
		return NUMA_NO_NODE;
	if (fscanf(file, "%d%c", &first, &sep) == 2) {
		if (sep == '-')
			second = first + 1;
		else if (sep == ',' && fscanf(file, "%d", &second) != 1)
			second = NUMA_NO_NODE;
	}
	fclose(file);
	return second;
}

static bool numa_balancing_enabled(void)
{
	FILE *file;
	int mode = 0;

	file = fopen("/proc/sys/kernel/numa_balancing", "r");
	if (!file)
		return false;
	if (fscanf(file, "%d", &mode) != 1)
		mode = 0;
	fclose(file);
	/* NUMA_BALANCING_NORMAL */
	return mode & 1;
}

/*
 * Run the workload in a new process until the scheduler is notified of a
 * preferred node change, for up to UPDATE_TIMEOUT seconds. A new thread
 * inherits the preferred node of the test, which may already match where its
 * memory is, but a new process starts without one and acquires one from the
 * hinting faults of the workload, whether or not its pages migrate. Return
 * false if the workload fails.
 */
static bool wait_for_update(struct numa_nid *skel)
{
	struct timespec start, now;
	bool ok = true;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return false;
	if (!pid) {
		while (run_workload())
			;
		_exit(1);
	}

	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		if (__atomic_load_n(&skel->bss->nr_updates, __ATOMIC_ACQUIRE))
			break;
		if (waitpid(pid, NULL, WNOHANG) == pid) {
			ok = false;
			pid = 0;
			break;
		}
		usleep(100000);
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while (now.tv_sec - start.tv_sec < UPDATE_TIMEOUT);

	if (pid) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
	return ok;
}

static enum scx_test_status setup(void **ctx)
{
	struct numa_nid *skel;

	skel = numa_nid__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	SCX_FAIL_IF(numa_nid__load(skel), "Failed to load skel");

	*ctx = skel;

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct numa_nid *skel = ctx;
	struct bpf_link *link;
	bool update;

	/*
	 * A preferred node change can only be expected on a machine with at
	 * least two memory nodes and numa_balancing enabled.
	 */
	update = second_memory_node() >= 0 && numa_balancing_enabled();
	if (!update)
		fprintf(stderr, "Skipping the preferred node update check\n");

	link = bpf_map__attach_struct_ops(skel->maps.numa_nid_ops);
	SCX_FAIL_IF(!link, "Failed to attach scheduler");

	/*
	 * Give the scan something to work on, so that the tasks of this test
	 * can acquire a preferred node on a NUMA machine with numa_balancing
	 * enabled. The scheduler reports an error through UEI if it ever sees
	 * a node id that is not valid and the counts below show what it saw.
	 */
	if (!run_workload() || (update && !wait_for_update(skel))) {
		SCX_ERR("Failed to run the workload");
		bpf_link__destroy(link);
		return SCX_TEST_FAIL;
	}

	fprintf(stderr, "notifications with a preferred node: %lu, without: %lu\n",
		(unsigned long)skel->bss->nr_with_nid,
		(unsigned long)skel->bss->nr_without_nid);

	bpf_link__destroy(link);
	SCX_EQ(skel->data->uei.kind, EXIT_KIND(SCX_EXIT_UNREG));
	SCX_GT(skel->bss->nr_enabled, 0);
	SCX_EQ(skel->bss->nr_initial, skel->bss->nr_enabled);
	fprintf(stderr, "initial notifications: %lu, updates: %lu\n",
		(unsigned long)skel->bss->nr_initial,
		(unsigned long)skel->bss->nr_updates);
	if (update)
		SCX_GT(skel->bss->nr_updates, 0);

	return SCX_TEST_PASS;
}

static void cleanup(void *ctx)
{
	struct numa_nid *skel = ctx;

	numa_nid__destroy(skel);
}

struct scx_test numa_nid = {
	.name = "numa_nid",
	.description = "Verify preferred NUMA node notifications to BPF",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&numa_nid)
