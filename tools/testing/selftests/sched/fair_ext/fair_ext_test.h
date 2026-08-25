/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */

#ifndef __FAIR_EXT_TEST_H
#define __FAIR_EXT_TEST_H

#include <stdio.h>

enum fair_ext_test_status {
	FAIR_EXT_TEST_PASS,
	FAIR_EXT_TEST_SKIP,
	FAIR_EXT_TEST_FAIL,
};

struct fair_ext_test {
	const char *name;
	const char *description;
	enum fair_ext_test_status (*setup)(void **ctx);
	enum fair_ext_test_status (*run)(void *ctx);
	void (*cleanup)(void *ctx);
};

void fair_ext_test_register(struct fair_ext_test *test);

#define REGISTER_FAIR_EXT_TEST(_test)			\
	static void __attribute__((constructor))		\
	register_fair_ext_test(void)			\
	{						\
		fair_ext_test_register(_test);		\
	}

#define FAIR_EXT_FAIL(_fmt, ...)			\
	do {						\
		fprintf(stderr, "ERROR: %s:%d: " _fmt "\n",\
			__FILE__, __LINE__, ##__VA_ARGS__);	\
		return FAIR_EXT_TEST_FAIL;		\
	} while (0)

#define FAIR_EXT_FAIL_IF(_cond, _fmt, ...)		\
	do {						\
		if (_cond)				\
			FAIR_EXT_FAIL(_fmt, ##__VA_ARGS__);\
	} while (0)

#define FAIR_EXT_VALUE(_x) ((unsigned long long)(_x))

#define FAIR_EXT_GT(_x, _y)					\
	FAIR_EXT_FAIL_IF((_x) <= (_y),				\
			 "Expected %s > %s (%llu > %llu)",	\
			 #_x, #_y, FAIR_EXT_VALUE(_x), FAIR_EXT_VALUE(_y))
#define FAIR_EXT_GE(_x, _y)					\
	FAIR_EXT_FAIL_IF((_x) < (_y),				\
			 "Expected %s >= %s (%llu >= %llu)",	\
			 #_x, #_y, FAIR_EXT_VALUE(_x), FAIR_EXT_VALUE(_y))
#define FAIR_EXT_EQ(_x, _y)					\
	FAIR_EXT_FAIL_IF((_x) != (_y),				\
			 "Expected %s == %s (%llu == %llu)",	\
			 #_x, #_y, FAIR_EXT_VALUE(_x), FAIR_EXT_VALUE(_y))
#define FAIR_EXT_ASSERT(_x)					\
	FAIR_EXT_FAIL_IF(!(_x), "Expected %s to be true", #_x)

#endif /* __FAIR_EXT_TEST_H */
