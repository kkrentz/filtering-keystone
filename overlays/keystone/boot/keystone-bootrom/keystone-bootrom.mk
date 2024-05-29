################################################################################
#
# bootrom
#
################################################################################

ifeq ($(KEYSTONE_BOOTROM),)
$(error KEYSTONE_BOOTROM directory not defined)
else
include $(KEYSTONE)/mkutils/pkg-keystone.mk
endif

KEYSTONE_BOOTROM_CONF_OPTS += KEYSTONE_ATTESTATION=${KEYSTONE_ATTESTATION}

define KEYSTONE_BOOTROM_BUILD_CMDS
	$(MAKE) $(TARGET_CONFIGURE_OPTS) -C $(@D) all
endef

KEYSTONE_BOOTROM_INSTALL_IMAGES = YES
define KEYSTONE_BOOTROM_INSTALL_IMAGES_CMDS
	$(INSTALL) -m 0644 -D $(@D)/bootrom.bin $(BINARIES_DIR)/bootrom.bin
	$(INSTALL) -m 0644 -D $(@D)/bootrom.elf $(BINARIES_DIR)/bootrom.elf
endef

$(eval $(keystone-package))
$(eval $(generic-package))
