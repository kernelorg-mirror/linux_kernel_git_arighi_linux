// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */
#define _GNU_SOURCE

#include <errno.h>
#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "fair_ext_flat_idle.bpf.skel.h"

static const char help_fmt[] =
"A flat fair_ext policy with fully custom BPF idle CPU tracking.\n"
"\n"
"Usage: %s [-v]\n"
"\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static volatile sig_atomic_t exit_req;
static bool verbose;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void signal_handler(int signo)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_test_run_opts, run_opts);
	struct fair_ext_flat_idle *skel = NULL;
	struct bpf_link *link = NULL;
	int nr_cpu_ids, opt, prog_fd;
	int err = 0;

	while ((opt = getopt(argc, argv, "vh")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	if (optind != argc) {
		fprintf(stderr, help_fmt, basename(argv[0]));
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	nr_cpu_ids = libbpf_num_possible_cpus();
	if (nr_cpu_ids < 0) {
		err = nr_cpu_ids;
		fprintf(stderr, "failed to determine possible CPUs: %s\n", strerror(-err));
		goto out;
	}

	skel = fair_ext_flat_idle__open();
	if (!skel) {
		err = -ENOMEM;
		fprintf(stderr, "failed to open BPF programs\n");
		goto out;
	}
	skel->rodata->nr_cpu_ids = nr_cpu_ids;

	err = fair_ext_flat_idle__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF programs: %s\n", strerror(-err));
		goto out;
	}

	prog_fd = bpf_program__fd(skel->progs.init_idle_mask);
	err = bpf_prog_test_run_opts(prog_fd, &run_opts);
	if (err || run_opts.retval) {
		err = err ?: -abs((int)run_opts.retval);
		fprintf(stderr, "failed to initialize idle CPU mask: %s\n", strerror(-err));
		goto out;
	}

	link = bpf_map__attach_struct_ops(skel->maps.fair_ext_flat_idle_ops);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		fprintf(stderr, "failed to attach fair_ext_flat_idle: %s\n", strerror(-err));
		goto out;
	}

	printf("fair_ext_flat_idle attached: topology=flat cpus=%d\n", nr_cpu_ids);
	while (!exit_req) {
		printf("idle_enter=%llu idle_exit=%llu select=%llu claimed=%llu fallback=%llu\n",
		       (unsigned long long)skel->bss->nr_idle_enter,
		       (unsigned long long)skel->bss->nr_idle_exit,
		       (unsigned long long)skel->bss->nr_select,
		       (unsigned long long)skel->bss->nr_claimed,
		       (unsigned long long)skel->bss->nr_fallback);
		fflush(stdout);
		sleep(1);
	}

out:
	bpf_link__destroy(link);
	fair_ext_flat_idle__destroy(skel);
	return err != 0;
}
