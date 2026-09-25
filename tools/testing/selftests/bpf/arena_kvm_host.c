// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arena_kvm_shared.h"

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_map *arena, *bss;
	uint32_t key = 0, offset;
	unsigned long parsed;
	int fd, err;
	char *end;

	if (argc != 5)
		return 1;
	errno = 0;
	parsed = strtoul(argv[1], &end, 0);
	if (errno || *end || parsed > INT_MAX)
		return 1;
	fd = dup(parsed);
	if (fd < 0)
		return 1;
	errno = 0;
	parsed = strtoul(argv[3], &end, 0);
	if (errno || *end || parsed > UINT_MAX ||
	    parsed >= ARENA_KVM_BYTES || (parsed & 4095))
		goto fail;
	offset = parsed;
	obj = bpf_object__open_file(argv[2], NULL);
	if (!obj)
		goto fail;
	arena = bpf_object__find_map_by_name(obj, "arena");
	bss = bpf_object__find_map_by_name(obj, ".bss");
	prog = bpf_object__find_program_by_name(obj, argv[4]);
	if (!arena || !bss || !prog || bpf_map__reuse_fd(arena, fd))
		goto fail;
	if (bpf_object__load(obj)) {
		fputs("load host BPF failed\n", stderr);
		goto fail;
	}
	if (bpf_map_update_elem(bpf_map__fd(bss), &key, &offset, BPF_ANY)) {
		perror("set signal offset");
		goto fail;
	}
	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (err)
		goto fail;
	printf("%u\n", opts.retval);
	bpf_object__close(obj);
	close(fd);
	return 0;

fail:
	bpf_object__close(obj);
	close(fd);
	return 1;
}
