# Copyright(C) 2018 Hex Five Security, Inc. - All Rights Reserved

TARGET = zone2.elf

BSP_BASE := ../bsp
PLATFORM_DIR := $(BSP_BASE)/$(BOARD)
NEWLIB_DIR := $(PLATFORM_DIR)/newlib

LINKER_SCRIPT := flash.lds

C_SRCS += main.c

ifneq ($(IPADDR),)
	CFLAGS += -DIPADDR="$(IPADDR)"
endif

ifneq ($(NETMASK),)
	CFLAGS += -DNETMASK="$(NETMASK)"
endif

CFLAGS += -DMZMSG_CHARS="$(MZMSG_CHARS)"

INCLUDES += -I../libhexfive -Ilib/picotcp/build/include
LDFLAGS += -L../libhexfive -Llib/picotcp/build/lib
LDFLAGS += $(if $(findstring rv64, $(RISCV_ARCH)), -lhexfive64, -lhexfive32) -lpicotcp

HEADERS += picotcp
LINK_DEPS += picotcp
CLEAN_OBJS += lib/picotcp/build

include $(NEWLIB_DIR)/newlib.mk

.PHONY: picotcp
picotcp:
	cd lib/picotcp && $(MAKE) clean
	cd lib/picotcp && $(MAKE)
