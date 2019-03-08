# Copyright(C) 2018 Hex Five Security, Inc. - All Rights Reserved

TARGET = zone1.elf

CFLAGS += -O2
LDFLAGS += -static --specs=nosys.specs 

BSP_BASE := ../bsp
PLATFORM_DIR := $(BSP_BASE)/$(BOARD)
NEWLIB_DIR := $(PLATFORM_DIR)/newlib

LINKER_SCRIPT := flash.lds

C_SRCS += main.c mzmsg.c cli.c
HEADERS += mzmsg.h cli.h

INCLUDES = -I.

INCLUDES += -I../ext/multizone
LDFLAGS += -L../ext/multizone
LDFLAGS += $(if $(findstring rv64, $(RISCV_ARCH)), -lhexfive64, -lhexfive32)

include $(NEWLIB_DIR)/newlib.mk
