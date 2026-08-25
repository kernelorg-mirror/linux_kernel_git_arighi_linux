// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */

#include <stdio.h>
#include <stdlib.h>

#include "fair_ext_test.h"

#define MAX_FAIR_EXT_TESTS 16

static struct fair_ext_test *tests[MAX_FAIR_EXT_TESTS];
static unsigned int nr_tests;

void fair_ext_test_register(struct fair_ext_test *test)
{
	if (!test || !test->name || !test->description || !test->run) {
		fprintf(stderr, "Invalid fair_ext test\n");
		exit(EXIT_FAILURE);
	}
	if (nr_tests == MAX_FAIR_EXT_TESTS) {
		fprintf(stderr, "Too many fair_ext tests\n");
		exit(EXIT_FAILURE);
	}

	tests[nr_tests++] = test;
}

static enum fair_ext_test_status run_test(const struct fair_ext_test *test)
{
	enum fair_ext_test_status status;
	void *ctx = NULL;

	if (test->setup) {
		status = test->setup(&ctx);
		if (status != FAIR_EXT_TEST_PASS)
			return status;
	}

	status = test->run(ctx);
	if (test->cleanup)
		test->cleanup(ctx);

	return status;
}

int main(void)
{
	unsigned int failed = 0;
	unsigned int i;

	printf("TAP version 13\n");
	printf("1..%u\n", nr_tests);

	for (i = 0; i < nr_tests; i++) {
		const struct fair_ext_test *test = tests[i];
		enum fair_ext_test_status status;

		printf("# %s\n", test->description);
		fflush(stdout);
		status = run_test(test);

		switch (status) {
		case FAIR_EXT_TEST_PASS:
			printf("ok %u - %s\n", i + 1, test->name);
			break;
		case FAIR_EXT_TEST_SKIP:
			printf("ok %u - %s # SKIP\n", i + 1, test->name);
			break;
		case FAIR_EXT_TEST_FAIL:
		default:
			printf("not ok %u - %s\n", i + 1, test->name);
			failed++;
			break;
		}
	}

	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
