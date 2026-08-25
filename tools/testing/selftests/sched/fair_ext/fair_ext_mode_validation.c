// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */

#include <stdlib.h>

#include <bpf/libbpf.h>

#include "fair_ext_mode_validation.bpf.skel.h"
#include "fair_ext_test.h"

struct fair_ext_mode_validation_ctx {
	struct fair_ext_mode_validation *skel;
};

static enum fair_ext_test_status setup(void **arg)
{
	struct fair_ext_mode_validation_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));
	FAIR_EXT_FAIL_IF(!ctx, "Failed to allocate context");
	*arg = ctx;

	return FAIR_EXT_TEST_PASS;
}

static void cleanup(void *arg)
{
	struct fair_ext_mode_validation_ctx *ctx = arg;

	fair_ext_mode_validation__destroy(ctx->skel);
	free(ctx);
}

static enum fair_ext_test_status test_mode_validation(void *arg)
{
	struct fair_ext_mode_validation_ctx *ctx = arg;
	struct bpf_link *link;

	ctx->skel = fair_ext_mode_validation__open_and_load();
	FAIR_EXT_FAIL_IF(!ctx->skel, "Failed to open and load BPF skeleton");

	link = bpf_map__attach_struct_ops(ctx->skel->maps.valid_migrate_ops);
	FAIR_EXT_FAIL_IF(libbpf_get_error(link), "Failed to attach migrate-only ops");
	bpf_link__destroy(link);

	link = bpf_map__attach_struct_ops(ctx->skel->maps.invalid_empty_ops);
	FAIR_EXT_ASSERT(libbpf_get_error(link));
	bpf_link__destroy(link);

	return FAIR_EXT_TEST_PASS;
}

struct fair_ext_test fair_ext_mode_validation = {
	.name = "fair_ext.mode_validation",
	.description = "Reject an empty sched_fair_ops instance",
	.setup = setup,
	.run = test_mode_validation,
	.cleanup = cleanup,
};

REGISTER_FAIR_EXT_TEST(&fair_ext_mode_validation)
