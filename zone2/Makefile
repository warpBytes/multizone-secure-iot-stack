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

PICOTCP_SRC_DIR := ../ext/picotcp
INCLUDES += -I../ext/multizone -I$(PICOTCP_SRC_DIR)/build/include
LDFLAGS += -L../ext/multizone -L$(PICOTCP_SRC_DIR)/build/lib
LDFLAGS += $(if $(findstring rv64, $(RISCV_ARCH)), -lhexfive64, -lhexfive32) -lpicotcp

HEADERS += picotcp
LINK_DEPS += picotcp
CLEAN_OBJS += $(PICOTCP_SRC_DIR)/build

include $(NEWLIB_DIR)/newlib.mk

.PHONY: picotcp
picotcp:
	cd $(PICOTCP_SRC_DIR) && $(MAKE) clean
	cd $(PICOTCP_SRC_DIR) && $(MAKE) \
		CROSS_COMPILE=$(abspath $(RISCV))/bin/riscv64-unknown-elf- \
		ARCH=rv32 \
		STRIP=0 \
		DEBUG=0 \
		PERF=0 \
		DEBUG_ALL=0 \
		GENERIC=0 \
		PROFILE=0 \
		TCP=1 \
		UDP=0 \
		ETH=1 \
		IPV4=1 \
		IPV6=0 \
		IPV4FRAG=1 \
		IPV6FRAG=0 \
		NAT=0 \
		ICMP4=1 \
		MCAST=0 \
		DEVLOOP=0 \
		DEVXEMACLITE=1 \
		PING=1 \
		DHCP_CLIENT=0 \
		DHCP_SERVER=0 \
		DNS_CLIENT=0 \
		MDNS=0 \
		DNS_SD=0 \
		SNTP_CLIENT=0 \
		IPFILTER=0 \
		CRC=0 \
		OLSR=0 \
		SLAACV4=0 \
		TFTP=0 \
		AODV=0 \
		MEMORY_MANAGER=0 \
		MEMORY_MANAGER_PROFILING=0 \
		TUN=0 \
		TAP=0 \
		PCAP=0 \
		PPP=0 \
		6LOWPAN=0 \
		IEEE802154=0 \
		IPC=0 \
		CYASSL=0 \
		WOLFSSL=0 \
		POLARSSL=0
