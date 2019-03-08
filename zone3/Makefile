# Copyright(C) 2018 Hex Five Security, Inc. - All Rights Reserved

TARGET = zone3.elf

BSP_BASE := ../bsp
PLATFORM_DIR := $(BSP_BASE)/$(BOARD)
NEWLIB_DIR := $(PLATFORM_DIR)/newlib

LINKER_SCRIPT := flash.lds

C_SRCS += main.c 

INCLUDES += -I. -I../ext/multizone
LDFLAGS += -L../ext/multizone
LDFLAGS += $(if $(findstring rv64, $(RISCV_ARCH)), -lhexfive64, -lhexfive32)

include $(NEWLIB_DIR)/newlib.mk
