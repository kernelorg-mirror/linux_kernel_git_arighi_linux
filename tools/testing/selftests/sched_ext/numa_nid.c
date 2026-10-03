// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA Corporation.
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <errno.h>
#include <linux/numa.h>
#include <pthread.h>
#include <sched.h>
#include <scx/common.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "numa_nid.bpf.skel.h"
#include "scx_test.h"

#define MIGRATION_SIZE		(4 << 20)
#define MIGRATION_SAMPLES	64
#define MIGRATION_TIMEOUT	30

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
 * The migration check runs when the machine has at least two memory nodes and
 * NUMA balancing is enabled. The test task pins itself to the first node and
 * faults in an anonymous area there, then its scheduler requests the second
 * node as the memory target. The task never runs on that node, so the only
 * thing that can move the pages there is the requested target.
 */
static bool migration;
static volatile char *migration_area;

static int first_memory_node(void)
{
	FILE *file;
	int nid = NUMA_NO_NODE;

	file = fopen("/sys/devices/system/node/has_memory", "r");
	if (!file)
		return NUMA_NO_NODE;
	if (fscanf(file, "%d", &nid) != 1)
		nid = NUMA_NO_NODE;
	fclose(file);
	return nid;
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

static int cpu_on_node(int nid, const cpu_set_t *allowed)
{
	char path[128];

	for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, allowed))
			continue;
		snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/cpu%d",
			 nid, cpu);
		if (!access(path, F_OK))
			return cpu;
	}
	return -1;
}

static void touch_migration_area(void)
{
	size_t offset;

	for (offset = 0; offset < MIGRATION_SIZE; offset += 4096)
		migration_area[offset]++;
}

static int pages_on_node(int nid)
{
	void *pages[MIGRATION_SAMPLES];
	int status[MIGRATION_SAMPLES];
	int count = 0;

	for (int sample = 0; sample < MIGRATION_SAMPLES; sample++)
		pages[sample] = (void *)&migration_area[sample * MIGRATION_SIZE /
							MIGRATION_SAMPLES];
	if (syscall(SYS_move_pages, 0, MIGRATION_SAMPLES, pages, NULL, status, 0))
		return -errno;
	for (int sample = 0; sample < MIGRATION_SAMPLES; sample++) {
		if (status[sample] < 0)
			return status[sample];
		count += status[sample] == nid;
	}
	return count;
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

/*
 * Pin the test to the first memory node and fault the migration area in
 * there. Return false, with the affinity left untouched, if that can't be done.
 */
static bool prepare_migration(cpu_set_t *saved_affinity)
{
	int source_nid = first_memory_node();
	cpu_set_t test_affinity;
	int source_cpu;

	if (sched_getaffinity(0, sizeof(*saved_affinity), saved_affinity))
		return false;
	source_cpu = cpu_on_node(source_nid, saved_affinity);
	if (source_cpu < 0) {
		fprintf(stderr, "No allowed CPU on node %d\n", source_nid);
		return false;
	}
	CPU_ZERO(&test_affinity);
	CPU_SET(source_cpu, &test_affinity);
	if (sched_setaffinity(0, sizeof(test_affinity), &test_affinity)) {
		fprintf(stderr, "Could not pin the test to node %d\n", source_nid);
		return false;
	}

	migration_area = mmap(NULL, MIGRATION_SIZE, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (migration_area == MAP_FAILED) {
		fprintf(stderr, "Could not map the migration area\n");
		goto restore;
	}
	madvise((void *)migration_area, MIGRATION_SIZE, MADV_NOHUGEPAGE);
	touch_migration_area();
	if (pages_on_node(source_nid) != MIGRATION_SAMPLES) {
		fprintf(stderr, "Test pages did not start on node %d\n", source_nid);
		munmap((void *)migration_area, MIGRATION_SIZE);
		goto restore;
	}
	return true;

restore:
	sched_setaffinity(0, sizeof(*saved_affinity), saved_affinity);
	return false;
}

/*
 * Keep accessing the migration area until at least half of the sampled pages
 * are on @target_nid. Return the number of sampled pages found there.
 */
static int exercise_migration(int target_nid)
{
	struct timespec start, now;
	int moved = 0;

	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		for (int iteration = 0; iteration < 1000; iteration++)
			touch_migration_area();
		moved = pages_on_node(target_nid);
		if (moved < 0 || moved >= MIGRATION_SAMPLES / 2)
			break;
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while (now.tv_sec - start.tv_sec < MIGRATION_TIMEOUT);
	return moved;
}

/*
 * Keep accessing the migration area, now on @target_nid, until the test task
 * is notified that its preferred node changed to @target_nid. Most of the
 * task's NUMA faults are on that node, so a placement pass sets it as the
 * preferred node, but only once the scan has gone through the address space
 * again. An earlier update may report another node, depending on the faults
 * taken before the pages moved. Return the last node reported in an update.
 */
static int exercise_preferred_node(struct numa_nid *skel, int target_nid)
{
	struct timespec start, now;
	int nid;

	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		for (int iteration = 0; iteration < 1000; iteration++)
			touch_migration_area();
		nid = __atomic_load_n(&skel->data->observed_update, __ATOMIC_ACQUIRE);
		if (nid == target_nid)
			break;
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while (now.tv_sec - start.tv_sec < MIGRATION_TIMEOUT);
	return nid;
}

static enum scx_test_status setup(void **ctx)
{
	struct numa_nid *skel;

	skel = numa_nid__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	skel->rodata->target_nid = first_memory_node();
	migration = second_memory_node() >= 0 && numa_balancing_enabled();
	if (migration)
		skel->rodata->target_nid = second_memory_node();
	skel->rodata->test_tid = gettid();
	SCX_FAIL_IF(numa_nid__load(skel), "Failed to load skel");

	*ctx = skel;

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct numa_nid *skel = ctx;
	struct bpf_link *link;
	enum scx_test_status status = SCX_TEST_PASS;
	cpu_set_t saved_affinity;
	int moved, nid;
	bool update;

	/*
	 * A preferred node change can only be expected on a machine with at
	 * least two memory nodes and numa_balancing enabled.
	 */
	update = second_memory_node() >= 0 && numa_balancing_enabled();
	if (!update)
		fprintf(stderr, "Skipping the preferred node update check\n");
	if (migration)
		migration = prepare_migration(&saved_affinity);
	if (!migration)
		fprintf(stderr, "Skipping the page migration check\n");

	link = bpf_map__attach_struct_ops(skel->maps.numa_nid_ops);
	if (!link) {
		SCX_ERR("Failed to attach scheduler");
		status = SCX_TEST_FAIL;
		goto restore_affinity;
	}

	/*
	 * Give the scan something to work on, so that the tasks of this test
	 * can acquire a preferred node on a NUMA machine with numa_balancing
	 * enabled. The scheduler reports an error through UEI if it ever sees
	 * a node id that is not valid and the counts below show what it saw.
	 *
	 * The test task goes through ops.running() while it does this, which
	 * is where the scheduler requests its memory target.
	 */
	if (!run_workload() || (update && !wait_for_update(skel))) {
		SCX_ERR("Failed to run the workload");
		status = SCX_TEST_FAIL;
		goto out;
	}

	if (skel->data->uei.kind != EXIT_KIND(SCX_EXIT_NONE)) {
		SCX_ERR("Scheduler exited");
		status = SCX_TEST_FAIL;
		goto out;
	}

	/*
	 * The memory target can only be tested if the kernel reports a memory
	 * node to request and is built with NUMA balancing.
	 */
	if (skel->rodata->target_nid == NUMA_NO_NODE) {
		fprintf(stderr, "No memory node found, skipping the NUMA target checks\n");
	} else if (skel->data->target_result == 1) {
		SCX_ERR("NUMA target kfunc was not exercised");
		status = SCX_TEST_FAIL;
		goto out;
	} else if (skel->data->target_result == -EOPNOTSUPP) {
		fprintf(stderr, "NUMA target not supported, skipping the NUMA target checks\n");
	} else {
		if (skel->data->invalid_result != -EINVAL ||
		    skel->data->target_result != 0 ||
		    skel->data->observed_target != skel->rodata->target_nid) {
			SCX_ERR("NUMA target kfunc did not set the requested node");
			status = SCX_TEST_FAIL;
			goto out;
		}
		if (migration) {
			moved = exercise_migration(skel->rodata->target_nid);
			fprintf(stderr, "NUMA migration: %d/%d sampled pages moved to node %d\n",
				moved, MIGRATION_SAMPLES, skel->rodata->target_nid);
			if (moved < MIGRATION_SAMPLES / 2) {
				SCX_ERR("Pages did not migrate to the NUMA target");
				status = SCX_TEST_FAIL;
				goto out;
			}

			nid = exercise_preferred_node(skel, skel->rodata->target_nid);
			fprintf(stderr, "Preferred node update: %d, expected %d\n",
				nid, skel->rodata->target_nid);
			if (nid != skel->rodata->target_nid) {
				SCX_ERR("No preferred node update to the NUMA target");
				status = SCX_TEST_FAIL;
				goto out;
			}
		}

		skel->bss->clear_target = true;
		for (int iteration = 0; iteration < 20 &&
		     __atomic_load_n(&skel->data->clear_result, __ATOMIC_ACQUIRE) == 1;
		     iteration++)
			usleep(100000);
		if (skel->data->clear_result != 0 ||
		    skel->data->observed_clear != NUMA_NO_NODE) {
			SCX_ERR("NUMA target kfunc did not clear the requested node");
			status = SCX_TEST_FAIL;
			goto out;
		}
	}

	fprintf(stderr, "notifications with a preferred node: %lu, without: %lu\n",
		(unsigned long)skel->bss->nr_with_nid,
		(unsigned long)skel->bss->nr_without_nid);
out:
	bpf_link__destroy(link);
	if (!skel->bss->nr_enabled ||
	    skel->bss->nr_initial != skel->bss->nr_enabled) {
		SCX_ERR("Missing initial NUMA node notifications");
		status = SCX_TEST_FAIL;
	}
	fprintf(stderr, "initial notifications: %lu, updates: %lu\n",
		(unsigned long)skel->bss->nr_initial,
		(unsigned long)skel->bss->nr_updates);
	if (update && !skel->bss->nr_updates) {
		SCX_ERR("No preferred node update");
		status = SCX_TEST_FAIL;
	}
	if (skel->data->uei.kind != EXIT_KIND(SCX_EXIT_UNREG)) {
		SCX_ERR("Scheduler did not exit cleanly");
		status = SCX_TEST_FAIL;
	}
restore_affinity:
	if (migration) {
		munmap((void *)migration_area, MIGRATION_SIZE);
		if (sched_setaffinity(0, sizeof(saved_affinity), &saved_affinity)) {
			SCX_ERR("Could not restore CPU affinity");
			status = SCX_TEST_FAIL;
		}
	}
	return status;
}

static void cleanup(void *ctx)
{
	struct numa_nid *skel = ctx;

	numa_nid__destroy(skel);
}

struct scx_test numa_nid = {
	.name = "numa_nid",
	.description = "Verify NUMA node notifications and memory target requests",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&numa_nid)
