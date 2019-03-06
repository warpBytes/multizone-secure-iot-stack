# Copyright(C) 2018 Hex Five Security, Inc. - All Rights Reserved

TARGET = zone2.elf

BSP_BASE := ../bsp
PLATFORM_DIR := $(BSP_BASE)/$(BOARD)
NEWLIB_DIR := $(PLATFORM_DIR)/newlib

LINKER_SCRIPT := flash.lds

C_SRCS += main.c

WOLFSSL_SRC_DIR := ../ext/wolfssl
# WOLFSSL TLS FILES
C_SRCS += $(WOLFSSL_SRC_DIR)/src/crl.c
C_SRCS += $(WOLFSSL_SRC_DIR)/src/internal.c
C_SRCS += $(WOLFSSL_SRC_DIR)/src/keys.c
C_SRCS += $(WOLFSSL_SRC_DIR)/src/ocsp.c
C_SRCS += $(WOLFSSL_SRC_DIR)/src/sniffer.c
C_SRCS += $(WOLFSSL_SRC_DIR)/src/ssl.c
C_SRCS += $(WOLFSSL_SRC_DIR)/src/tls.c
C_SRCS += $(WOLFSSL_SRC_DIR)/src/tls13.c
C_SRCS += $(WOLFSSL_SRC_DIR)/src/wolfio.c

# Defines
CFLAGS += -DWOLFSSL_USER_SETTINGS

# wolfCrypt Core
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/aes.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/cmac.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/des3.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/dh.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/ecc.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/hmac.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/random.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/rsa.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/sha.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/sha256.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/sha512.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/sha3.c

# wolfCrypt Additional
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/asn.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/chacha.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/coding.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/compress.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/cpuid.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/cryptocb.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/curve25519.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/ed25519.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/error.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/fe_low_mem.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/fe_operations.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/ge_low_mem.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/ge_operations.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/hash.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/integer.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/logging.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/md5.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/memory.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/pkcs12.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/pkcs7.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/poly1305.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/pwdbased.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/signature.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/srp.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/sp_arm32.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/sp_arm64.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/sp_c32.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/sp_int.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/tfm.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/wc_encrypt.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/wc_port.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/wolfevent.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/wolfmath.c

# wolfCrypt non-standard algorithms (disabled by default)
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/arc4.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/blake2b.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/camellia.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/dsa.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/hc128.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/idea.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/md2.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/md4.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/rabbit.c
C_SRCS += $(WOLFSSL_SRC_DIR)/wolfcrypt/src/ripemd.c

ifneq ($(IPADDR),)
	CFLAGS += -DIPADDR="$(IPADDR)"
endif

ifneq ($(NETMASK),)
	CFLAGS += -DNETMASK="$(NETMASK)"
endif

PICOTCP_SRC_DIR := ../ext/picotcp
INCLUDES += -I. -I../ext/multizone -I$(PICOTCP_SRC_DIR)/build/include -I$(WOLFSSL_SRC_DIR)
LDFLAGS += -L../ext/multizone -L$(PICOTCP_SRC_DIR)/build/lib
LDFLAGS += $(if $(findstring rv64, $(RISCV_ARCH)), -lhexfive64, -lhexfive32) -lpicotcp -lm

HEADERS += picotcp
LINK_DEPS += picotcp
CLEAN_OBJS += $(PICOTCP_SRC_DIR)/build

include $(NEWLIB_DIR)/newlib.mk

CFLAGS += -Os -g3

.PHONY: picotcp
picotcp:
	cd $(PICOTCP_SRC_DIR) && "$(MAKE)" clean
	cd $(PICOTCP_SRC_DIR) && "$(MAKE)" \
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
