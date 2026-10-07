AM2_NAND_WINDOW_VERSION = 1.0.0
AM2_NAND_WINDOW_SITE = $(BR2_EXTERNAL_DCENTOS_PATH)/../scripts/first_install
AM2_NAND_WINDOW_SITE_METHOD = local
AM2_NAND_WINDOW_LICENSE = GPL-3.0-only
AM2_NAND_WINDOW_LICENSE_FILES = am2_nand_window.c

define AM2_NAND_WINDOW_BUILD_CMDS
	$(TARGET_CC) $(TARGET_CFLAGS) -std=c11 -Wall -Wextra -Werror $(TARGET_LDFLAGS) \
		-o $(@D)/am2-nand-window $(@D)/am2_nand_window.c
endef

define AM2_NAND_WINDOW_INSTALL_TARGET_CMDS
	install -D -m 0755 $(@D)/am2-nand-window \
		$(TARGET_DIR)/usr/libexec/dcentos/am2-nand-window
	install -D -m 0755 $(BR2_EXTERNAL_DCENTOS_PATH)/../scripts/lib/am2_ota_boot.py \
		$(TARGET_DIR)/usr/libexec/dcentos/am2_ota_boot.py
	install -D -m 0644 $(BR2_EXTERNAL_DCENTOS_PATH)/../scripts/prepare_am2_fabric_boot.py \
		$(TARGET_DIR)/usr/libexec/dcentos/prepare_am2_fabric_boot.py
	install -D -m 0755 $(BR2_EXTERNAL_DCENTOS_PATH)/board/zynq/rootfs-overlay/usr/libexec/dcentos/am2-native-ota.sh \
		$(TARGET_DIR)/usr/libexec/dcentos/am2-native-ota.sh
	install -D -m 0755 $(BR2_EXTERNAL_DCENTOS_PATH)/board/zynq/rootfs-overlay/usr/sbin/dcent-am2-ota-rollback \
		$(TARGET_DIR)/usr/sbin/dcent-am2-ota-rollback
endef

$(eval $(generic-package))
