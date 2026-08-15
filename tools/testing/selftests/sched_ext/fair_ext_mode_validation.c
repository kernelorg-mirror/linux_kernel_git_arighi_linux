// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */

#include <stdlib.h>

#include <bpf/libbpf.h>

#include "fair_ext_mode_validation.bpf.skel.h"
#include "scx_test.h"

struct fair_ext_mode_validation_ctx {
	struct fair_ext_mode_validation *skel;
};

static enum scx_test_status setup(void **arg)
{
	struct fair_ext_mode_validation_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));
	SCX_FAIL_IF(!ctx, "Failed to allocate context");
	*arg = ctx;

	return SCX_TEST_PASS;
}

static void cleanup(void *arg)
{
	struct fair_ext_mode_validation_ctx *ctx = arg;
	fair_ext_mode_validation__destroy(ctx->skel);
	free(ctx);
}

static enum scx_test_status test_mode_validation(void *arg)
{
	struct fair_ext_mode_validation_ctx *ctx = arg;
	struct bpf_link *link;

	ctx->skel = fair_ext_mode_validation__open_and_load();
	SCX_FAIL_IF(!ctx->skel, "Failed to open and load BPF skeleton");

	link = bpf_map__attach_struct_ops(ctx->skel->maps.invalid_mixed_ops);
	SCX_ASSERT(libbpf_get_error(link));
	bpf_link__destroy(link);

	link = bpf_map__attach_struct_ops(ctx->skel->maps.invalid_regular_ops);
	SCX_ASSERT(libbpf_get_error(link));
	bpf_link__destroy(link);

	link = bpf_map__attach_struct_ops(ctx->skel->maps.invalid_empty_fair_ops);
	SCX_ASSERT(libbpf_get_error(link));
	bpf_link__destroy(link);

	return SCX_TEST_PASS;
}

struct scx_test fair_ext_mode_validation = {
	.name = "fair_ext.mode_validation",
	.description = "Reject mixed regular and fair sched_ext operations",
	.setup = setup,
	.run = test_mode_validation,
	.cleanup = cleanup,
};

REGISTER_SCX_TEST(&fair_ext_mode_validation)
