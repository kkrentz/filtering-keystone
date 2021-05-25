#############
## Headers ##
#############

# General headers
keystone-sm-headers += assert.h cpu.h enclave.h ipi.h mprv.h page.h platform-hook.h \
                        pmp.h safe_math_util.h sm.h sm-sbi.h sm-sbi-opensbi.h thread.h

# Crypto headers
keystone-sm-headers += crypto.h micro-ecc/uECC.h sha-256/sha-256.h

# Platform headers
keystone-sm-headers += platform/$(KEYSTONE_PLATFORM)/platform.h

ifeq ($(KEYSTONE_PLATFORM),sifive/fu540)
	keystone-sm-headers += platform/sifive/fu540/waymasks.h
endif

# Plugin headers
keystone-sm-headers += plugins/multimem.h plugins/plugins.h

##################
## Source files ##
##################

# Core files
keystone-sm-sources += attest.c cpu.c enclave.c pmp.c sm.c sm-sbi.c sm-sbi-opensbi.c \
                        thread.c mprv.c sbi_trap_hack.c trap.c ipi.c

# Crypto
keystone-sm-sources += crypto.c micro-ecc/uECC.c sha-256/sha-256.c

# Platform
keystone-sm-sources += platform/$(PLATFORM)/platform.c

# Plugin files
keystone-sm-sources += plugins/multimem.c plugins/plugins.c
