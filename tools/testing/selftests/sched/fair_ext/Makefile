# SPDX-License-Identifier: GPL-2.0
include ../../../../build/Build.include
include ../../../../scripts/Makefile.arch
include ../../../../scripts/Makefile.include

TEST_GEN_PROGS := runner

OVERRIDE_TARGETS := 1
include ../../lib.mk

CURDIR := $(abspath .)
REPOROOT := $(abspath ../../../../..)
TOOLSDIR := $(REPOROOT)/tools
LIBDIR := $(TOOLSDIR)/lib
BPFDIR := $(LIBDIR)/bpf
TOOLSINCDIR := $(TOOLSDIR)/include
BPFTOOLDIR := $(TOOLSDIR)/bpf/bpftool
APIDIR := $(TOOLSINCDIR)/uapi
GENDIR := $(REPOROOT)/include/generated
FAIR_EXT_INCDIR := $(TOOLSDIR)/sched/fair_ext/include

OUTPUT_DIR := $(OUTPUT)/build
OBJ_DIR := $(OUTPUT_DIR)/obj
INCLUDE_DIR := $(OUTPUT_DIR)/include
BPFOBJ_DIR := $(OBJ_DIR)/libbpf
FAIR_EXT_OBJ_DIR := $(OBJ_DIR)/fair_ext
BPFOBJ := $(BPFOBJ_DIR)/libbpf.a
LIBBPF_OUTPUT := $(OBJ_DIR)/libbpf/libbpf.a

DEFAULT_BPFTOOL := $(OUTPUT_DIR)/host/sbin/bpftool
HOST_OBJ_DIR := $(OBJ_DIR)/host/bpftool
HOST_LIBBPF_OUTPUT := $(OBJ_DIR)/host/libbpf/
HOST_LIBBPF_DESTDIR := $(OUTPUT_DIR)/host/
HOST_DESTDIR := $(OUTPUT_DIR)/host/

VMLINUX_BTF_PATHS ?= $(if $(O),$(O)/vmlinux) \
		     $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux) \
		     ../../../../../vmlinux \
		     /sys/kernel/btf/vmlinux \
		     /boot/vmlinux-$(shell uname -r)
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))
ifeq ($(VMLINUX_BTF),)
$(error Cannot find vmlinux BTF in "$(VMLINUX_BTF_PATHS)")
endif

BPFTOOL ?= $(DEFAULT_BPFTOOL)

ifneq ($(wildcard $(GENDIR)/autoconf.h),)
GENFLAGS := -DHAVE_GENHDR
endif

CFLAGS += -g -O2 -rdynamic -pthread -Wall -Werror $(GENFLAGS) \
	  -I$(INCLUDE_DIR) -I$(GENDIR) -I$(LIBDIR) \
	  -I$(TOOLSINCDIR) -I$(APIDIR) -I$(CURDIR)
LDFLAGS := -lelf -lz -lpthread -lzstd

IS_LITTLE_ENDIAN = $(shell $(CC) -dM -E - </dev/null | \
			grep 'define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__')

define get_sys_includes
$(shell $(1) $(2) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }') \
$(shell $(1) $(2) -dM -E - </dev/null | grep '__riscv_xlen ' \
	| awk '{printf("-D__riscv_xlen=%d -D__BITS_PER_LONG=%d", $$3, $$3)}')
endef

ifneq ($(CROSS_COMPILE),)
CLANG_TARGET_ARCH = --target=$(notdir $(CROSS_COMPILE:%-=%))
endif

BPF_CFLAGS = -g -D__TARGET_ARCH_$(SRCARCH) \
	     $(if $(IS_LITTLE_ENDIAN),-mlittle-endian,-mbig-endian) \
	     -I$(INCLUDE_DIR) -I$(APIDIR) -I$(FAIR_EXT_INCDIR) \
	     -I$(REPOROOT)/include \
	     $(call get_sys_includes,$(CLANG),$(CLANG_TARGET_ARCH)) \
	     -Wall -Wno-compare-distinct-pointer-types \
	     -Wno-incompatible-function-pointer-types \
	     -Wno-microsoft-anon-tag -fms-extensions -O2 -mcpu=v3

MAKE_DIRS := $(sort $(BPFOBJ_DIR) $(HOST_OBJ_DIR) $(INCLUDE_DIR) \
	       $(FAIR_EXT_OBJ_DIR))

$(MAKE_DIRS):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $@

$(BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile) \
	   $(APIDIR)/linux/bpf.h | $(BPFOBJ_DIR)
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR) OUTPUT=$(BPFOBJ_DIR)/ \
		ARCH=$(ARCH) CC="$(CC)" CROSS_COMPILE=$(CROSS_COMPILE) \
		EXTRA_CFLAGS='-g -O0 -fPIC' DESTDIR=$(OUTPUT_DIR) \
		prefix= all install_headers

$(DEFAULT_BPFTOOL): $(wildcard $(BPFTOOLDIR)/*.[ch] $(BPFTOOLDIR)/Makefile) \
		    $(LIBBPF_OUTPUT) | $(HOST_OBJ_DIR)
	$(Q)$(MAKE) $(submake_extras) -C $(BPFTOOLDIR) ARCH= CROSS_COMPILE= \
		CC=$(HOSTCC) LD=$(HOSTLD) EXTRA_CFLAGS='-g -O0' \
		OUTPUT=$(HOST_OBJ_DIR)/ LIBBPF_OUTPUT=$(HOST_LIBBPF_OUTPUT) \
		LIBBPF_DESTDIR=$(HOST_LIBBPF_DESTDIR) prefix= \
		DESTDIR=$(HOST_DESTDIR) install-bin

$(INCLUDE_DIR)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL) | $(INCLUDE_DIR)
	$(call msg,GEN,,$@)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(FAIR_EXT_OBJ_DIR)/%.bpf.o: %.bpf.c $(INCLUDE_DIR)/vmlinux.h | \
				     $(BPFOBJ) $(FAIR_EXT_OBJ_DIR)
	$(call msg,CLNG-BPF,,$(notdir $@))
	$(Q)$(CLANG) $(BPF_CFLAGS) -target bpf -c $< -o $@

$(INCLUDE_DIR)/%.bpf.skel.h: $(FAIR_EXT_OBJ_DIR)/%.bpf.o \
				    $(INCLUDE_DIR)/vmlinux.h $(BPFTOOL)
	$(call msg,GEN-SKEL,,$(notdir $@))
	$(Q)$(BPFTOOL) gen skeleton $< \
		name $(subst .bpf.skel.h,,$(notdir $@)) > $@

test-names := fair_ext_mode_validation fair_ext_operations fair_ext_watchdog
test-objs := $(addsuffix .o,$(addprefix $(FAIR_EXT_OBJ_DIR)/,$(test-names)))
test-skels := $(addsuffix .bpf.skel.h,$(addprefix $(INCLUDE_DIR)/,$(test-names)))

$(FAIR_EXT_OBJ_DIR)/runner.o: runner.c | $(FAIR_EXT_OBJ_DIR) $(BPFOBJ)
	$(CC) $(CFLAGS) -c $< -o $@

$(test-objs): $(FAIR_EXT_OBJ_DIR)/%.o: %.c $(test-skels) | $(FAIR_EXT_OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUTPUT)/runner: $(FAIR_EXT_OBJ_DIR)/runner.o $(BPFOBJ) $(test-objs)
	$(CC) $(CFLAGS) -o $@ $(FAIR_EXT_OBJ_DIR)/runner.o $(test-objs) \
		$(BPFOBJ) $(LDFLAGS)

override define CLEAN
	rm -rf $(OUTPUT_DIR)
	rm -f $(TEST_GEN_PROGS)
endef

.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.SECONDARY:
