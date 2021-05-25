march ?= rv64imafdc
mabi ?= lp64
CC ?= riscv64-unknown-elf-gcc
OBJCOPY ?= riscv64-unknown-elf-objcopy

CFLAGS = \
	-march=$(march) -mcmodel=medany -mabi=$(mabi) \
	-nostdlib -nostartfiles -fno-common -std=gnu11 \
	-static \
	-fPIC \
	-DuECC_BYTES=32 \
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
	${SM_DIR}/src/micro-ecc/uECC.c \
	${SM_DIR}/src/sha-256/sha-256.c

%.elf: $(bootrom_sources) bootloader.lds
	$(CC) $(CFLAGS) -I./ -I${SM_DIR}/src/micro-ecc/ -I${SM_DIR}/src/sha-256/ -L . -T bootloader.lds -o $@ $(bootrom_sources)

%.bin: %.elf
	$(OBJCOPY) -O binary --only-section=.text $< $@;

