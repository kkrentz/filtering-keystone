#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates.
#
# Authors:
#   Atish Patra <atish.patra@wdc.com>
#
PLATFORM = mpfs
KEYSTONE_SM_REL=../../
platform-genflags-y += "-DTARGET_PLATFORM_HEADER=\"platform/$(PLATFORM)/platform.h\""

platform-objs-y += $(KEYSTONE_SM_REL)src/attest.o
platform-objs-y += $(KEYSTONE_SM_REL)src/cpu.o
platform-objs-y += $(KEYSTONE_SM_REL)src/crypto.o
platform-objs-y += $(KEYSTONE_SM_REL)src/enclave.o
platform-objs-y += $(KEYSTONE_SM_REL)src/pmp.o
platform-objs-y += $(KEYSTONE_SM_REL)src/sm.o
platform-objs-y += $(KEYSTONE_SM_REL)src/sm-sbi.o
platform-objs-y += $(KEYSTONE_SM_REL)src/sm-sbi-opensbi.o
platform-objs-y += $(KEYSTONE_SM_REL)src/thread.o
platform-objs-y += $(KEYSTONE_SM_REL)src/mprv.o
platform-objs-y += $(KEYSTONE_SM_REL)src/sbi_trap_hack.o
platform-objs-y += $(KEYSTONE_SM_REL)src/trap.o
platform-objs-y += $(KEYSTONE_SM_REL)src/ipi.o

platform-objs-y += $(KEYSTONE_SM_REL)src/micro-ecc/uECC.o
platform-objs-y += $(KEYSTONE_SM_REL)src/sha-256/sha-256.o

platform-objs-y += $(KEYSTONE_SM_REL)src/platform/$(PLATFORM)/platform.o

platform-objs-y += $(KEYSTONE_SM_REL)src/plugins/plugins.o

platform-objs-y += platform.o
platform-objs-y += uart_helper.o
platform-objs-y += csr_helper.o
platform-objs-y += hss_clock.o
platform-objs-y += drivers/mss_uart/mss_uart.o
platform-objs-y += drivers/mss_sys_services/mss_sys_services.o
