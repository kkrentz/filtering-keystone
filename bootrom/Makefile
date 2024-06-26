
# We override some of the variables that we get from the Buildroot
# infrastructure here. Specifically, we don't want to use the provided
# CFLAGS since these assume that the build target isn't firmware-like
# (i.e. we want nostdlib, nostartfiles, etc).

override CFLAGS := \
	-mcmodel=medany \
	-nostdlib -nostartfiles -fno-common -std=gnu11 \
	-static \
	-fPIC \
	-DuECC_BYTES=32 \
	-DuECC_WORD_SIZE=8 \
	-DuECC_CURVE=uECC_secp256r1 \
	-DKEYSTONE_BOOTLOADER=1 \
	-DuECC_SUPPORTS_secp160r1=0 \
	-DuECC_SUPPORTS_secp192r1=0 \
	-DuECC_SUPPORTS_secp224r1=0 \
	-DuECC_SUPPORTS_secp256r1=1 \
	-DuECC_SUPPORTS_secp256k1=0 \
	-DuECC_ENABLE_VLI_API=1 \
	-O2 -Wall
O ?=.

# ^ consider taking out -g -Og and putting in -O2

bootloaders=\
	$(O)/bootrom.elf \
	$(O)/bootrom.bin

.PHONY: all
all: $(bootloaders)

.PHONY: clean
clean:
	rm -f $(bootloaders)

bootrom_sources = \
	./bootloader.S \
	./bootloader.c \
	string.c \
	${KEYSTONE_SM}/src/micro-ecc/uECC.c \
	${KEYSTONE_SM}/src/libcoap/src/oscore-ng/oscore_ng_sha_256.c

%.elf: $(bootrom_sources) bootloader.lds
	$(CC) \
		$(CFLAGS) \
		-I./ \
		-I${KEYSTONE_SM}/src/micro-ecc/ \
		-I${KEYSTONE_SM}/src/ \
		-L . \
		-T bootloader.lds \
		-o $@ $(bootrom_sources)

%.bin: %.elf
	$(OBJCOPY) -O binary --only-section=.text $< $@;

