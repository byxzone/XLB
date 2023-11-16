USER_TARGETS += xlb_client
USER_TARGETS += xlb_server

COMMON_DIR = ../common

# Extend with another COMMON_OBJS
COMMON_OBJS += $(COMMON_DIR)/common_user_bpf_xdp.o

EXTRA_DEPS := $(COMMON_DIR)/parsing_helpers.h

XLB_OBJS += metric.o rs_hash.o ../xlb_core/map_common.o

include $(COMMON_DIR)/common.mk

