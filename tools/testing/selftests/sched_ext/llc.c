// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sys/wait.h>
#include <unistd.h>
#include "llc.bpf.skel.h"
#include "scx_test.h"

static enum scx_test_status setup(void **ctx)
{
	struct llc *skel;

	skel = llc__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	SCX_FAIL_IF(llc__load(skel), "Failed to load skel");

	*ctx = skel;

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct llc *skel = ctx;
	struct bpf_link *link;

	link = bpf_map__attach_struct_ops(skel->maps.llc_ops);
	SCX_FAIL_IF(!link, "Failed to attach scheduler");

	/* Just sleeping is fine, plenty of scheduling events happening */
	sleep(1);

	SCX_EQ(skel->data->uei.kind, EXIT_KIND(SCX_EXIT_NONE));
	bpf_link__destroy(link);

	return SCX_TEST_PASS;
}

static void cleanup(void *ctx)
{
	struct llc *skel = ctx;

	llc__destroy(skel);
}

struct scx_test llc = {
	.name = "llc",
	.description = "Verify LLC-aware functionalities",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&llc)
