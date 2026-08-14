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

#include "scx_fair_nvcsw.bpf.skel.h"

static const char help_fmt[] =
"A fair_ext policy which boosts positive virtual lag for tasks with high "
"voluntary context-switch rates.\n"
"\n"
"Usage: %s [-v]\n"
"\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static volatile sig_atomic_t exit_req;
static bool verbose;

struct scx_fair_nvcsw_stats {
	__u64 nr_select;
	__u64 nr_override;
};

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

static int read_stats(struct scx_fair_nvcsw *skel,
		      struct scx_fair_nvcsw_stats *totals)
{
	int nr_cpus = libbpf_num_possible_cpus();
	struct scx_fair_nvcsw_stats *values;
	__u32 idx = 0;
	int cpu, ret;

	if (nr_cpus < 1)
		return nr_cpus ?: -EINVAL;

	values = calloc(nr_cpus, sizeof(*values));
	if (!values)
		return -ENOMEM;

	ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &idx, values);
	if (ret) {
		ret = -errno;
		goto out;
	}

	memset(totals, 0, sizeof(*totals));
	for (cpu = 0; cpu < nr_cpus; cpu++) {
		totals->nr_select += values[cpu].nr_select;
		totals->nr_override += values[cpu].nr_override;
	}

out:
	free(values);
	return ret;
}

int main(int argc, char **argv)
{
	struct scx_fair_nvcsw *skel = NULL;
	struct scx_fair_nvcsw_stats stats;
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

	skel = scx_fair_nvcsw__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open and load BPF programs\n");
		return 1;
	}

	link = bpf_map__attach_struct_ops(skel->maps.scx_fair_nvcsw_ops);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		fprintf(stderr, "failed to attach scx_fair_nvcsw: %s\n",
			strerror(-err));
		goto out;
	}

	printf("scx_fair_nvcsw attached\n");
	while (!exit_req) {
		err = read_stats(skel, &stats);
		if (err) {
			fprintf(stderr, "failed to read statistics: %s\n",
				strerror(-err));
			goto out;
		}
		printf("select=%llu override=%llu\n",
		       (unsigned long long)stats.nr_select,
		       (unsigned long long)stats.nr_override);
		fflush(stdout);
		sleep(1);
	}

out:
	bpf_link__destroy(link);
	scx_fair_nvcsw__destroy(skel);
	return err != 0;
}
