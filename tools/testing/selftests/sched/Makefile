# SPDX-License-Identifier: GPL-2.0+

ifneq ($(shell $(CC) --version 2>&1 | head -n 1 | grep clang),)
CLANG_FLAGS += -no-integrated-as
endif

CFLAGS += -O2 -Wall -g -I./ $(KHDR_INCLUDES) -Wl,-rpath=./ \
	  $(CLANG_FLAGS)
LDLIBS += -lpthread

TEST_GEN_FILES := cs_prctl_test
TEST_PROGS := cs_prctl_test
SUBDIRS := fair_ext

include ../lib.mk

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) OUTPUT=$(OUTPUT)/$@ -C $@ all

override define RUN_TESTS
	BASE_DIR="$(selfdir)"; \
	. $(selfdir)/kselftest/runner.sh; \
	run_many $(1); \
	$(MAKE) OUTPUT=$(OUTPUT)/fair_ext -C fair_ext run_tests
endef

override define CLEAN
	$(RM) -r $(TEST_GEN_FILES)
	$(MAKE) OUTPUT=$(OUTPUT)/fair_ext -C fair_ext clean
endef

.PHONY: $(SUBDIRS)
