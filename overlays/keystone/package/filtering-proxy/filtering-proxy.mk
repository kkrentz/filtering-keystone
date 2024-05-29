################################################################################
#
# Filtering proxy
#
################################################################################

ifeq ($(FILTERING_PROXY),)
$(error FILTERING_PROXY directory not defined)
else
include $(KEYSTONE)/mkutils/pkg-keystone.mk
endif

FILTERING_PROXY_DEPENDENCIES += host-keystone-sdk keystone-runtime filtering-libcoap
FILTERING_PROXY_CONF_OPTS += -DKEYSTONE_SDK_DIR=$(HOST_DIR)/usr/share/keystone/sdk \
                             -DKEYSTONE_EYRIE_RUNTIME=$(KEYSTONE_RUNTIME_BUILDDIR) \
                             -DLIBCOAP_INSTALL_PATH=$(TARGET_DIR)/usr/local
ifeq ($(KEYSTONE_ATTESTATION),sigma)
FILTERING_PROXY_CONF_OPTS += -DWITH_TRAP=OFF
FILTERING_PROXY_CONF_OPTS += -DWITH_IRAP=OFF
else ifeq ($(KEYSTONE_ATTESTATION),trap)
FILTERING_PROXY_CONF_OPTS += -DWITH_TRAP=ON
FILTERING_PROXY_CONF_OPTS += -DWITH_IRAP=OFF
else ifeq ($(KEYSTONE_ATTESTATION),irap)
FILTERING_PROXY_CONF_OPTS += -DWITH_TRAP=ON
FILTERING_PROXY_CONF_OPTS += -DWITH_IRAP=ON
else
$(error KEYSTONE_ATTESTATION must either be sigma, trap, or irap)
endif
FILTERING_PROXY_MAKE_OPTS += filtering-proxy

# Install .ke file and overlay
define FILTERING_PROXY_INSTALL_TARGET_CMDS
	find $(@D) -name '*.ke' | \
                xargs -i{} $(INSTALL) -D -m 755 -t $(TARGET_DIR)/root/ {}
    cp $(FILTERING_PROXY)/overlay/run.sh $(TARGET_DIR)/root/
endef

$(eval $(keystone-package))
$(eval $(cmake-package))
