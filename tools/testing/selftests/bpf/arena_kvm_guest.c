// SPDX-License-Identifier: GPL-2.0
/* Guest helper for a BPF arena allocated from shared NUMA RAM. */
#define _GNU_SOURCE
#define __EXPORTED_HEADERS__

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define TIMEOUT_SECONDS 45

static uint32_t get_u32(const unsigned char *p)
{
	uint32_t value;

	memcpy(&value, p, sizeof(value));
	return value;
}

static uint64_t get_u64(const unsigned char *p)
{
	uint64_t value;

	memcpy(&value, p, sizeof(value));
	return value;
}

static int signal_file_offset(void *arena, uint64_t *offset)
{
	const char *srat_path = "/sys/firmware/acpi/tables/SRAT";
	unsigned char srat[65536];
	uint64_t entry, pfn, gpa, base, length;
	size_t pos, table_length;
	ssize_t n;
	int fd;

	/* Fault the BPF-allocated page into the guest user VMA. */
	if (!*(volatile uint64_t *)arena)
		return -EINVAL;
	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0)
		return -errno;
	n = pread(fd, &entry, sizeof(entry),
		  (uintptr_t)arena / PAGE_SIZE * sizeof(entry));
	close(fd);
	if (n != sizeof(entry) || !(entry & (1ULL << 63)))
		return -EIO;
	pfn = entry & ((1ULL << 55) - 1);
	if (!pfn)
		return -EPERM;
	gpa = pfn * PAGE_SIZE;

	fd = open(srat_path, O_RDONLY);
	if (fd < 0)
		return -errno;
	n = read(fd, srat, sizeof(srat));
	close(fd);
	if (n < 48)
		return -EIO;
	table_length = get_u32(srat + 4);
	if (table_length > (size_t)n || table_length < 48)
		return -EINVAL;
	for (pos = 48; pos + 2 <= table_length; pos += srat[pos + 1]) {
		if (srat[pos + 1] < 2 || pos + srat[pos + 1] > table_length)
			return -EINVAL;
		if (srat[pos] != 1 || srat[pos + 1] < 40 ||
		    get_u32(srat + pos + 2) != 1 ||
		    !(get_u32(srat + pos + 28) & 1))
			continue;
		base = get_u64(srat + pos + 8);
		length = get_u64(srat + pos + 16);
		if (length != 1ULL * 1024 * 1024 || gpa < base ||
		    gpa - base >= length)
			continue;
		*offset = gpa - base;
		return 0;
	}
	return -ERANGE;
}

static int create_arena(void)
{
	union bpf_attr attr = {
		.map_type = BPF_MAP_TYPE_ARENA,
		.max_entries = 1,
		.map_flags = BPF_F_MMAPABLE | BPF_F_ARENA_NO_FREE,
	};

	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int run_prog(int fd, unsigned int *retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err = bpf_prog_test_run_opts(fd, &opts);

	if (err)
		return err;
	*retval = opts.retval;
	return 0;
}

static int exchange_once(int fd)
{
	struct timespec start, now;
	unsigned int result = 0;
	int err;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		err = run_prog(fd, &result);
		if (err || result > 1)
			return err ? err : -EINVAL;
		if (!result)
			return 0;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec >= TIMEOUT_SECONDS)
			return -ETIMEDOUT;
		usleep(1000);
	}
}

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *alloc, *probe_free, *exchange, *complete;
	struct bpf_map *map;
	void *arena = MAP_FAILED;
	uint64_t file_offset;
	unsigned int result = 0;
	int fd = -1;
	int err;

	setbuf(stdout, NULL);
	if (argc != 2 ||
	    (mount("sysfs", "/sys", "sysfs", 0, NULL) && errno != EBUSY) ||
	    (mount("proc", "/proc", "proc", 0, NULL) && errno != EBUSY))
		goto fail;
	if (access("/sys/devices/system/node/node1", F_OK)) {
		fputs("guest NUMA node 1 is unavailable\n", stderr);
		goto fail;
	}
	fd = create_arena();
	if (fd < 0) {
		perror("create guest arena");
		goto fail;
	}
	arena = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (arena == MAP_FAILED) {
		perror("mmap guest arena");
		goto fail;
	}
	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj)
		goto fail;
	map = bpf_object__find_map_by_name(obj, "arena");
	alloc = bpf_object__find_program_by_name(obj, "allocate");
	probe_free = bpf_object__find_program_by_name(obj, "probe_free");
	exchange = bpf_object__find_program_by_name(obj, "exchange");
	complete = bpf_object__find_program_by_name(obj, "complete");
	if (!map || !alloc || !probe_free || !exchange || !complete ||
	    bpf_map__reuse_fd(map, fd))
		goto fail;
	close(fd);
	fd = -1;
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load guest BPF: %d\n", err);
		goto fail;
	}
	err = run_prog(bpf_program__fd(alloc), &result);
	if (err || result) {
		fprintf(stderr, "allocate guest page: err=%d result=%u\n",
			err, result);
		goto fail;
	}
	err = run_prog(bpf_program__fd(probe_free), &result);
	if (err || result) {
		fprintf(stderr, "guest page lifetime check: err=%d result=%u\n",
			err, result);
		goto fail;
	}
	err = signal_file_offset(arena, &file_offset);
	if (err) {
		fprintf(stderr, "resolve shared page offset: %d\n", err);
		goto fail;
	}
	printf("GUEST_BPF_READY %llu\n", (unsigned long long)file_offset);
	if (exchange_once(bpf_program__fd(exchange)) ||
	    exchange_once(bpf_program__fd(exchange)) ||
	    exchange_once(bpf_program__fd(complete)))
		goto fail;
	puts("GUEST_BPF_EXCHANGED");
	bpf_object__close(obj);
	munmap(arena, PAGE_SIZE);
	return 0;

fail:
	puts("GUEST_BPF_FAILED");
	bpf_object__close(obj);
	if (arena != MAP_FAILED)
		munmap(arena, PAGE_SIZE);
	if (fd >= 0)
		close(fd);
	return 1;
}
