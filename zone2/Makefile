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

INCLUDES += -I. -I../ext/multizone
LDFLAGS += -L../ext/multizone
LDFLAGS += $(if $(findstring rv64, $(RISCV_ARCH)), -lhexfive64, -lhexfive32) -lm

include $(NEWLIB_DIR)/newlib.mk

CFLAGS += -O0
