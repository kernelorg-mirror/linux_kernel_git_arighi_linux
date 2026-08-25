# SPDX-License-Identifier: GPL-2.0
include ../../build/Build.include
include ../../scripts/Makefile.arch
include ../../scripts/Makefile.include

all: all_targets

CURDIR := $(abspath .)
REPOROOT := $(abspath ../../..)
TOOLSDIR := $(REPOROOT)/tools
LIBDIR := $(TOOLSDIR)/lib
BPFDIR := $(LIBDIR)/bpf
TOOLSINCDIR := $(TOOLSDIR)/include
BPFTOOLDIR := $(TOOLSDIR)/bpf/bpftool
APIDIR := $(TOOLSINCDIR)/uapi
GENDIR := $(REPOROOT)/include/generated

OUTPUT_DIR := $(if $(O),$(O)/build,$(CURDIR)/build)
OBJ_DIR := $(OUTPUT_DIR)/obj
INCLUDE_DIR := $(OUTPUT_DIR)/include
BPFOBJ_DIR := $(OBJ_DIR)/libbpf
FAIR_EXT_OBJ_DIR := $(OBJ_DIR)/fair_ext
BINDIR := $(OUTPUT_DIR)/bin
HOST_BPFOBJ := $(BPFOBJ_DIR)/libbpf.a
DEFAULT_BPFTOOL := $(OUTPUT_DIR)/sbin/bpftool

VMLINUX_BTF_PATHS ?= $(if $(O),$(O)/vmlinux) \
		     $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux) \
		     ../../../vmlinux /sys/kernel/btf/vmlinux \
		     /boot/vmlinux-$(shell uname -r)
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))
ifeq ($(VMLINUX_BTF),)
$(error Cannot find vmlinux BTF in "$(VMLINUX_BTF_PATHS)")
endif

BPFTOOL ?= $(DEFAULT_BPFTOOL)

ifneq ($(wildcard $(GENDIR)/autoconf.h),)
GENFLAGS := -DHAVE_GENHDR
endif

CFLAGS += -g -O2 -pthread -Wall -Werror $(GENFLAGS) \
	  -I$(INCLUDE_DIR) -I$(GENDIR) -I$(LIBDIR) \
	  -I$(TOOLSINCDIR) -I$(APIDIR) -I$(CURDIR)/include
LDFLAGS += -rdynamic -lelf -lz -lpthread

IS_LITTLE_ENDIAN = $(shell $(CC) -dM -E - </dev/null | \
			grep 'define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__')

define get_sys_includes
$(shell $(1) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
endef

BPF_CFLAGS = -g -D__TARGET_ARCH_$(SRCARCH) \
	     $(if $(IS_LITTLE_ENDIAN),-mlittle-endian,-mbig-endian) \
	     -I$(INCLUDE_DIR) -I$(APIDIR) -I$(CURDIR)/include \
	     -I$(REPOROOT)/include $(call get_sys_includes,$(CLANG)) \
	     -Wall -Wno-compare-distinct-pointer-types \
	     -Wno-microsoft-anon-tag -fms-extensions -O2 -mcpu=v3

MAKE_DIRS := $(sort $(BPFOBJ_DIR) $(OBJ_DIR)/bpftool $(INCLUDE_DIR) \
	       $(FAIR_EXT_OBJ_DIR) $(BINDIR))

$(MAKE_DIRS):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $@

$(HOST_BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile) \
		$(APIDIR)/linux/bpf.h | $(BPFOBJ_DIR)
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR) OUTPUT=$(BPFOBJ_DIR)/ \
		ARCH= CROSS_COMPILE= CC="$(HOSTCC)" LD=$(HOSTLD) \
		EXTRA_CFLAGS='-g -O0 -fPIC' DESTDIR=$(OUTPUT_DIR) \
		prefix= all install_headers

$(DEFAULT_BPFTOOL): $(wildcard $(BPFTOOLDIR)/*.[ch] $(BPFTOOLDIR)/Makefile) \
		    $(HOST_BPFOBJ) | $(OBJ_DIR)/bpftool
	$(Q)$(MAKE) $(submake_extras) -C $(BPFTOOLDIR) ARCH= CROSS_COMPILE= \
		CC="$(HOSTCC)" LD=$(HOSTLD) EXTRA_CFLAGS='-g -O0' \
		OUTPUT=$(OBJ_DIR)/bpftool/ LIBBPF_OUTPUT=$(BPFOBJ_DIR)/ \
		LIBBPF_DESTDIR=$(OUTPUT_DIR)/ prefix= DESTDIR=$(OUTPUT_DIR)/ \
		install-bin

$(INCLUDE_DIR)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL) | $(INCLUDE_DIR)
	$(call msg,GEN,,$@)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(FAIR_EXT_OBJ_DIR)/%.bpf.o: %.bpf.c $(INCLUDE_DIR)/vmlinux.h \
				     include/fair_ext/*.h | $(FAIR_EXT_OBJ_DIR)
	$(call msg,CLNG-BPF,,$(notdir $@))
	$(Q)$(CLANG) $(BPF_CFLAGS) -target bpf -c $< -o $@

$(INCLUDE_DIR)/%.bpf.skel.h: $(FAIR_EXT_OBJ_DIR)/%.bpf.o \
				    $(INCLUDE_DIR)/vmlinux.h $(BPFTOOL)
	$(call msg,GEN-SKEL,,$(notdir $@))
	$(Q)$(BPFTOOL) gen skeleton $< \
		name $(subst .bpf.skel.h,,$(notdir $@)) > $@

fair-ext-targets := fair_ext_flat_idle fair_ext_noop fair_ext_tiered

$(addprefix $(BINDIR)/,$(fair-ext-targets)): $(BINDIR)/%: %.c \
		$(INCLUDE_DIR)/%.bpf.skel.h $(HOST_BPFOBJ) | $(BINDIR)
	$(CC) $(CFLAGS) -c $< -o $(FAIR_EXT_OBJ_DIR)/$*.o
	$(CC) -o $@ $(FAIR_EXT_OBJ_DIR)/$*.o $(HOST_BPFOBJ) $(LDFLAGS)

$(fair-ext-targets): %: $(BINDIR)/%
all_targets: $(fair-ext-targets)

install: all
	$(Q)mkdir -p $(DESTDIR)/usr/local/bin/
	$(Q)cp $(addprefix $(BINDIR)/,$(fair-ext-targets)) \
		$(DESTDIR)/usr/local/bin/

clean:
	rm -rf $(OUTPUT_DIR)

.PHONY: all all_targets install clean $(fair-ext-targets)
.DELETE_ON_ERROR:
.SECONDARY:
