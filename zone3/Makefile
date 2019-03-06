# Copyright(C) 2018 Hex Five Security, Inc. - All Rights Reserved

TARGET = zone3.elf

BSP_BASE := ../bsp
PLATFORM_DIR := $(BSP_BASE)/$(BOARD)
NEWLIB_DIR := $(PLATFORM_DIR)/newlib

LINKER_SCRIPT := flash.lds

C_SRCS += main.c 

WOLFSSL_SRC_DIR := ../ext/wolfssl

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

INCLUDES += -I. -I../ext/multizone -I${WOLFSSL_SRC_DIR}
LDFLAGS += -L../ext/multizone
LDFLAGS += $(if $(findstring rv64, $(RISCV_ARCH)), -lhexfive64, -lhexfive32)

include $(NEWLIB_DIR)/newlib.mk
