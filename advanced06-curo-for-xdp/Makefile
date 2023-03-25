# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := af_xdp_kern
USER_TARGETS := af_xdp_user

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

USER_OBJ += ../../build/libcuro.so

include $(COMMON_DIR)/common.mk
LIBS += -lpthread ../../build/libcuro.so

CFLAGS += -I../../
LDFLAGS += -Wl,--copy-dt-needed-entries