// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 *
 * Verify that SCX_OPS_ENQ_BLOCKED delegates proxy donor admission to BPF.
 */
#define _GNU_SOURCE

#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <scx/common.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "enq_blocked.bpf.skel.h"
#include "enq_blocked.h"
#include "scx_test.h"

#define MODULE_NAME	"scx_enq_blocked_test"
#define MODULE_FILE	"test_modules/" MODULE_NAME ".ko"
#define DEVICE_PATH	"/dev/scx_enq_blocked"
#define WAIT_STEP_US	1000
#define WAIT_TIMEOUT_MS	2000

struct thread_ctx {
	atomic_bool start_donor;
	atomic_bool abort;
	atomic_int donor_pid;
	int fd;
	int cpu;
};

static bool parse_bool(const char *value, bool *result)
{
	if (!strcasecmp(value, "1") || !strcasecmp(value, "y") ||
	    !strcasecmp(value, "yes") || !strcasecmp(value, "on") ||
	    !strcasecmp(value, "true")) {
		*result = true;
		return true;
	}

	if (!strcasecmp(value, "0") || !strcasecmp(value, "n") ||
	    !strcasecmp(value, "no") || !strcasecmp(value, "off") ||
	    !strcasecmp(value, "false")) {
		*result = false;
		return true;
	}

	return false;
}

static bool cmdline_bool(const char *name, bool default_value)
{
	char cmdline[4096], *newline, *saveptr = NULL, *token;
	size_t name_len = strlen(name);
	bool value = default_value;
	FILE *file;

	file = fopen("/proc/cmdline", "r");
	if (!file)
		return default_value;

	if (!fgets(cmdline, sizeof(cmdline), file)) {
		fclose(file);
		return default_value;
	}
	fclose(file);
	newline = strchr(cmdline, '\n');
	if (newline)
		*newline = '\0';

	for (token = strtok_r(cmdline, " ", &saveptr); token;
	     token = strtok_r(NULL, " ", &saveptr)) {
		bool parsed;

		if (strncmp(token, name, name_len) || token[name_len] != '=')
			continue;
		if (parse_bool(token + name_len + 1, &parsed))
			value = parsed;
	}

	return value;
}

static int module_path(char *path, size_t size)
{
	ssize_t len;
	char *slash;

	len = readlink("/proc/self/exe", path, size - 1);
	if (len < 0)
		return -errno;
	path[len] = '\0';

	slash = strrchr(path, '/');
	if (!slash)
		return -EINVAL;
	*slash = '\0';

	if (snprintf(slash, size - (slash - path), "/%s", MODULE_FILE) >=
	    size - (slash - path))
		return -ENAMETOOLONG;

	return 0;
}

static int load_test_module(bool *loaded_here)
{
	char path[PATH_MAX];
	int fd, err;

	err = module_path(path, sizeof(path));
	if (err)
		return err;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	if (syscall(SYS_finit_module, fd, "", 0)) {
		err = errno;
		close(fd);
		if (err == EEXIST)
			return 0;
		return -err;
	}

	close(fd);
	*loaded_here = true;
	return 0;
}

static void unload_test_module(bool loaded_here)
{
	if (loaded_here && syscall(SYS_delete_module, MODULE_NAME, O_NONBLOCK))
		SCX_ERR("Failed to unload %s (%d)", MODULE_NAME, errno);
}

static int pin_to_cpu(int cpu)
{
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	return sched_setaffinity(0, sizeof(mask), &mask) ? errno : 0;
}

static bool wait_for_pid(atomic_int *pid)
{
	int waited_ms;

	for (waited_ms = 0; waited_ms < WAIT_TIMEOUT_MS; waited_ms++) {
		if (atomic_load_explicit(pid, memory_order_acquire) > 0)
			return true;
		usleep(WAIT_STEP_US);
	}

	return false;
}

static void *owner_fn(void *arg)
{
	struct thread_ctx *ctx = arg;
	int err;

	err = pin_to_cpu(ctx->cpu);
	if (err)
		return (void *)(uintptr_t)err;

	if (ioctl(ctx->fd, ENQ_BLOCKED_IOCTL_OWNER))
		return (void *)(uintptr_t)errno;

	return NULL;
}

static void *donor_fn(void *arg)
{
	struct thread_ctx *ctx = arg;
	int err;

	err = pin_to_cpu(ctx->cpu);
	if (err)
		return (void *)(uintptr_t)err;

	atomic_store_explicit(&ctx->donor_pid, syscall(SYS_gettid),
			      memory_order_release);
	while (!atomic_load_explicit(&ctx->start_donor, memory_order_acquire) &&
	       !atomic_load_explicit(&ctx->abort, memory_order_relaxed))
		sched_yield();

	if (atomic_load_explicit(&ctx->abort, memory_order_relaxed))
		return NULL;

	do {
		err = ioctl(ctx->fd, ENQ_BLOCKED_IOCTL_DONOR);
	} while (err && errno == EAGAIN);

	return err ? (void *)(uintptr_t)errno : NULL;
}

static int join_thread(pthread_t thread)
{
	void *result;
	int err;

	err = pthread_join(thread, &result);
	if (err)
		return err;

	return (int)(uintptr_t)result;
}

static enum scx_test_status setup(void **ctx)
{
	struct enq_blocked *skel;
	u64 flag;

	skel = enq_blocked__open();
	SCX_FAIL_IF(!skel, "Failed to open skel");
	SCX_ENUM_INIT(skel);

	flag = SCX_OPS_ENQ_BLOCKED;
	if (!flag) {
		enq_blocked__destroy(skel);
		fprintf(stderr, "SKIP: SCX_OPS_ENQ_BLOCKED is unavailable\n");
		return SCX_TEST_SKIP;
	}

	skel->struct_ops.enq_blocked_ops->flags = flag;
	SCX_FAIL_IF(enq_blocked__load(skel), "Failed to load skel");

	*ctx = skel;
	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct enq_blocked *skel = ctx;
	struct thread_ctx thread_ctx = {};
	struct bpf_link *link = NULL;
	pthread_t owner, donor;
	cpu_set_t mask;
	bool module_loaded = false;
	bool owner_started = false, donor_started = false;
	bool proxy_enabled;
	enum scx_test_status status = SCX_TEST_PASS;
	int cpu, donor_pid, err;
	u64 nr_blocked;

	proxy_enabled = cmdline_bool("sched_proxy_exec", true) &&
			cmdline_bool("sched_proxy_exec_scx", false);

	err = load_test_module(&module_loaded);
	if (err == -EPERM || err == -ENOENT) {
		fprintf(stderr, "SKIP: cannot load mutex fixture (%d)\n", -err);
		return SCX_TEST_SKIP;
	}
	SCX_FAIL_IF(err, "Failed to load mutex fixture (%d)", -err);

	thread_ctx.fd = open(DEVICE_PATH, O_RDONLY | O_CLOEXEC);
	if (thread_ctx.fd < 0) {
		SCX_ERR("Failed to open %s (%d)", DEVICE_PATH, errno);
		status = SCX_TEST_FAIL;
		goto out_module;
	}

	if (sched_getaffinity(0, sizeof(mask), &mask)) {
		SCX_ERR("Failed to get CPU affinity (%d)", errno);
		status = SCX_TEST_FAIL;
		goto out_fd;
	}
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &mask))
			break;
	}
	if (cpu == CPU_SETSIZE) {
		status = SCX_TEST_SKIP;
		goto out_fd;
	}
	thread_ctx.cpu = cpu;

	link = bpf_map__attach_struct_ops(skel->maps.enq_blocked_ops);
	if (!link) {
		SCX_ERR("Failed to attach scheduler");
		status = SCX_TEST_FAIL;
		goto out_fd;
	}

	err = pthread_create(&owner, NULL, owner_fn, &thread_ctx);
	if (err) {
		SCX_ERR("Failed to create owner thread (%d)", err);
		status = SCX_TEST_FAIL;
		goto out;
	}
	owner_started = true;

	err = pthread_create(&donor, NULL, donor_fn, &thread_ctx);
	if (err) {
		SCX_ERR("Failed to create donor thread (%d)", err);
		status = SCX_TEST_FAIL;
		goto out;
	}
	donor_started = true;

	if (!wait_for_pid(&thread_ctx.donor_pid)) {
		SCX_ERR("Timed out waiting for donor thread");
		status = SCX_TEST_FAIL;
		goto out;
	}

	donor_pid = atomic_load_explicit(&thread_ctx.donor_pid,
					 memory_order_acquire);
	skel->bss->donor_pid = donor_pid;
	atomic_store_explicit(&thread_ctx.start_donor, true,
			      memory_order_release);

out:
	if (status != SCX_TEST_PASS) {
		atomic_store_explicit(&thread_ctx.abort, true, memory_order_release);
		atomic_store_explicit(&thread_ctx.start_donor, true,
				      memory_order_release);
	}

	if (donor_started) {
		err = join_thread(donor);
		if (err) {
			SCX_ERR("Donor thread failed (%d)", err);
			status = SCX_TEST_FAIL;
		}
	}
	if (owner_started) {
		err = join_thread(owner);
		if (err) {
			SCX_ERR("Owner thread failed (%d)", err);
			status = SCX_TEST_FAIL;
		}
	}

	nr_blocked = skel->bss->nr_blocked_enqueues;
	printf("nr_blocked_enqueues=%llu\n", (unsigned long long)nr_blocked);
	if (status == SCX_TEST_PASS) {
		if (proxy_enabled && !nr_blocked) {
			SCX_ERR("ops.enqueue() did not receive the blocked donor");
			status = SCX_TEST_FAIL;
		} else if (!proxy_enabled && nr_blocked) {
			SCX_ERR("ops.enqueue() received %llu blocked donors with proxy disabled",
				(unsigned long long)nr_blocked);
			status = SCX_TEST_FAIL;
		}
	}

	if (skel->data->uei.kind != EXIT_KIND(SCX_EXIT_NONE)) {
		SCX_ERR("Scheduler exited unexpectedly (kind=%llu code=%lld)",
			(unsigned long long)skel->data->uei.kind,
			(long long)skel->data->uei.exit_code);
		status = SCX_TEST_FAIL;
	}

	if (link)
		bpf_link__destroy(link);
out_fd:
	close(thread_ctx.fd);
out_module:
	unload_test_module(module_loaded);
	return status;
}

static void cleanup(void *ctx)
{
	struct enq_blocked *skel = ctx;

	enq_blocked__destroy(skel);
}

struct scx_test enq_blocked = {
	.name = "enq_blocked",
	.description = "Verify BPF-driven proxy donor admission",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};

REGISTER_SCX_TEST(&enq_blocked)
