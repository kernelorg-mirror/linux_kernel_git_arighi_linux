// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */
#define _GNU_SOURCE

#include <errno.h>
#include <libgen.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "scx_fair_tiered.bpf.skel.h"

static const char help_fmt[] =
"A tiered fair_ext CPU-placement policy.\n"
"\n"
"CPU placement prefers idle CPUs in CPU-LIST and falls back to unrestricted\n"
"fair placement when they are busy.\n"
"\n"
"Usage: %s -c CPU-LIST [-v]\n"
"\n"
"  -c CPU-LIST   Preferred CPUs, for example 0-3,8,10-11\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static volatile sig_atomic_t exit_req;
static bool verbose;

struct scx_fair_tiered_stats {
	__u64 nr_select;
	__u64 nr_select_preferred;
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

static int read_stats(struct scx_fair_tiered *skel,
		      struct scx_fair_tiered_stats *totals)
{
	int nr_cpus = libbpf_num_possible_cpus();
	struct scx_fair_tiered_stats *values;
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
		totals->nr_select_preferred += values[cpu].nr_select_preferred;
	}

out:
	free(values);
	return ret;
}

static int parse_cpu(const char *str, unsigned long *cpu, int nr_possible_cpus)
{
	char *end;

	errno = 0;
	*cpu = strtoul(str, &end, 10);
	if (errno || end == str || *end || *cpu >= nr_possible_cpus)
		return -EINVAL;
	return 0;
}

static int parse_cpu_list(const char *list, cpu_set_t *mask, size_t mask_size,
			  int nr_possible_cpus)
{
	char *copy, *cursor, *token;
	bool populated = false;
	int ret = 0;

	copy = strdup(list);
	if (!copy)
		return -ENOMEM;
	cursor = copy;

	while ((token = strsep(&cursor, ","))) {
		unsigned long first, last, cpu;
		char *dash;

		if (!*token) {
			ret = -EINVAL;
			break;
		}

		dash = strchr(token, '-');
		if (dash) {
			*dash++ = '\0';
			if (!*dash || strchr(dash, '-')) {
				ret = -EINVAL;
				break;
			}
		}

		ret = parse_cpu(token, &first, nr_possible_cpus);
		if (ret)
			break;
		if (dash) {
			ret = parse_cpu(dash, &last, nr_possible_cpus);
			if (ret)
				break;
		} else {
			last = first;
		}
		if (last < first) {
			ret = -EINVAL;
			break;
		}

		for (cpu = first; cpu <= last; cpu++)
			CPU_SET_S(cpu, mask_size, mask);
		populated = true;
	}

	free(copy);
	return ret ?: (populated ? 0 : -EINVAL);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_test_run_opts, run_opts);
	struct scx_fair_tiered *skel = NULL;
	struct bpf_link *link = NULL;
	cpu_set_t *preferred_cpus = NULL;
	const char *cpu_list = NULL;
	struct scx_fair_tiered_stats stats;
	__u64 args[1];
	size_t preferred_size;
	int nr_possible_cpus, opt, err = 0;

	while ((opt = getopt(argc, argv, "c:vh")) != -1) {
		switch (opt) {
		case 'c':
			cpu_list = optarg;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	if (optind != argc || !cpu_list) {
		fprintf(stderr, help_fmt, basename(argv[0]));
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	skel = scx_fair_tiered__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	nr_possible_cpus = libbpf_num_possible_cpus();
	if (nr_possible_cpus < 1) {
		err = nr_possible_cpus ?: -EINVAL;
		fprintf(stderr, "failed to determine possible CPUs: %s\n",
			strerror(-err));
		goto out;
	}

	preferred_size = CPU_ALLOC_SIZE(nr_possible_cpus);
	preferred_cpus = CPU_ALLOC(nr_possible_cpus);
	if (!preferred_cpus) {
		err = -ENOMEM;
		goto out;
	}
	CPU_ZERO_S(preferred_size, preferred_cpus);

	err = parse_cpu_list(cpu_list, preferred_cpus, preferred_size,
			     nr_possible_cpus);
	if (err) {
		fprintf(stderr, "invalid CPU list: %s\n", cpu_list);
		goto out;
	}

	err = scx_fair_tiered__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF programs: %s\n",
			strerror(-err));
		goto out;
	}

	err = bpf_prog_test_run_opts(
		bpf_program__fd(skel->progs.init_preferred_mask), &run_opts);
	if (err || run_opts.retval) {
		err = err ?: -abs((int)run_opts.retval);
		fprintf(stderr, "failed to initialize CPU mask: %s\n",
			strerror(-err));
		goto out;
	}

	for (int cpu = 0; cpu < nr_possible_cpus; cpu++) {
		int prog_fd;

		if (!CPU_ISSET_S(cpu, preferred_size, preferred_cpus))
			continue;

		args[0] = cpu;
		run_opts.ctx_in = args;
		run_opts.ctx_size_in = sizeof(args);
		prog_fd = bpf_program__fd(skel->progs.add_preferred_cpu);
		err = bpf_prog_test_run_opts(prog_fd, &run_opts);
		if (err || run_opts.retval) {
			err = err ?: -abs((int)run_opts.retval);
			fprintf(stderr, "failed to add CPU %d: %s\n", cpu,
				strerror(-err));
			goto out;
		}
	}

	link = bpf_map__attach_struct_ops(skel->maps.scx_fair_tiered_ops);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		fprintf(stderr, "failed to attach scx_fair_tiered: %s\n",
			strerror(-err));
		goto out;
	}

	printf("scx_fair_tiered attached: preferred_cpus=%s\n", cpu_list);
	while (!exit_req) {
		err = read_stats(skel, &stats);
		if (err) {
			fprintf(stderr, "failed to read statistics: %s\n",
				strerror(-err));
			goto out;
		}
		printf("select=%llu preferred=%llu\n",
		       (unsigned long long)stats.nr_select,
		       (unsigned long long)stats.nr_select_preferred);
		fflush(stdout);
		sleep(1);
	}

out:
	bpf_link__destroy(link);
	scx_fair_tiered__destroy(skel);
	CPU_FREE(preferred_cpus);
	return err != 0;
}
