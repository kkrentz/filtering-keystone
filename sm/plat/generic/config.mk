# Here, we just include the config.mk from the standard generic implementation
include $(src_dir)/platform/$(PLATFORM)/config.mk

# We do need to make sure to include headers for the SM
ifeq ($(KEYSTONE_SM),)
$(error KEYSTONE_SM not defined for SM)
endif

ifeq ($(KEYSTONE_SDK_DIR),)
$(error KEYSTONE_SDK_DIR not defined)
endif

platform-cflags-y = -I$(KEYSTONE_SM)/src -I$(src_dir)/platform/$(PLATFORM)/include \
                        -I$(KEYSTONE_SDK_DIR)/include/shared
platform-cflags-y += -DKEYSTONE_SM=1
platform-cflags-y += -DuECC_BYTES=32
platform-cflags-y += -DuECC_WORD_SIZE=8
platform-cflags-y += -DuECC_CURVE=uECC_secp256r1
platform-cflags-y += -DuECC_SUPPORTS_secp160r1=0
platform-cflags-y += -DuECC_SUPPORTS_secp192r1=0
platform-cflags-y += -DuECC_SUPPORTS_secp224r1=0
platform-cflags-y += -DuECC_SUPPORTS_secp256r1=1
platform-cflags-y += -DuECC_SUPPORTS_secp256k1=0
platform-cflags-y += -DuECC_ENABLE_VLI_API=1
