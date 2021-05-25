#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2020 Western Digital Corporation or its affiliates.
#
# Authors:
#   Anup Patel <anup.patel@wdc.com>
#

# Compiler flags
platform-cppflags-y =
platform-cflags-y = -I../src
platform-cflags-y += -DKEYSTONE_SM=1
platform-cflags-y += -DuECC_BYTES=32
platform-cflags-y += -DuECC_CURVE=uECC_secp256r1
platform-cflags-y += -DuECC_SUPPORTS_secp160r1=0
platform-cflags-y += -DuECC_SUPPORTS_secp192r1=0
platform-cflags-y += -DuECC_SUPPORTS_secp224r1=0
platform-cflags-y += -DuECC_SUPPORTS_secp256r1=1
platform-cflags-y += -DuECC_SUPPORTS_secp256k1=0
platform-cflags-y += -DuECC_ENABLE_VLI_API=1
platform-asflags-y =
platform-ldflags-y =

# Command for platform specific "make run"
platform-runcmd = qemu-system-riscv$(PLATFORM_RISCV_XLEN) -M virt -m 256M \
  -nographic -bios $(build_dir)/platform/generic/firmware/fw_payload.elf

# Blobs to build
FW_TEXT_START=0x80000000
FW_DYNAMIC=y
FW_JUMP=y
ifeq ($(PLATFORM_RISCV_XLEN), 32)
  # This needs to be 4MB aligned for 32-bit system
  FW_JUMP_ADDR=$(shell printf "0x%X" $$(($(FW_TEXT_START) + 0x400000)))
else
  # This needs to be 2MB aligned for 64-bit system
  FW_JUMP_ADDR=$(shell printf "0x%X" $$(($(FW_TEXT_START) + 0x200000)))
endif
FW_JUMP_FDT_ADDR=$(shell printf "0x%X" $$(($(FW_TEXT_START) + 0x2200000)))
FW_PAYLOAD=y
ifeq ($(PLATFORM_RISCV_XLEN), 32)
  # This needs to be 4MB aligned for 32-bit system
  FW_PAYLOAD_OFFSET=0x400000
else
  # This needs to be 2MB aligned for 64-bit system
  FW_PAYLOAD_OFFSET=0x200000
endif
FW_PAYLOAD_FDT_ADDR=$(FW_JUMP_FDT_ADDR)
