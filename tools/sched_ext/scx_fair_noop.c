// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */
#define _GNU_SOURCE

#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "scx_fair_noop.bpf.skel.h"

static const char help_fmt[] =
"A no-op fair_ext policy for measuring callback overhead.\n"
"\n"
"Usage: %s [-v]\n"
"\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static volatile sig_atomic_t exit_req;
static bool verbose;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
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
	struct scx_fair_noop *skel = NULL;
	struct bpf_link *link = NULL;
	int opt, err = 0;

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

	skel = scx_fair_noop__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open and load BPF programs\n");
		return 1;
	}

	link = bpf_map__attach_struct_ops(skel->maps.scx_fair_noop_ops);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		fprintf(stderr, "failed to attach scx_fair_noop: %s\n",
			strerror(-err));
		goto out;
	}

	printf("scx_fair_noop attached\n");
	while (!exit_req)
		pause();

out:
	bpf_link__destroy(link);
	scx_fair_noop__destroy(skel);
	return err != 0;
}
