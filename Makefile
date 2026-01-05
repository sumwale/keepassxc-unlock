SHELL = /bin/bash

SRC_DIR = src
BUILD_DIR := $(shell realpath ./build)
SYSTEMD_DIR = systemd
INSTALL_ROOT =
INSTALL_BIN_DIR = /usr/local/sbin
INSTALL_SERVICE_DIR = /etc/systemd/system
PKG_INSTALL = false
PRODUCT_VERSION := $(shell bash ./version.sh)
DEFAULT_PLATFORMS = linux/x86_64 linux/aarch64

export BUILD_DIR PRODUCT_VERSION

.PHONY: all all-static all-static-musl mk_builddir clean install uninstall package

all: mk_builddir
	$(MAKE) -C $(SRC_DIR)
	$(MAKE) -C $(SYSTEMD_DIR)

all-static: mk_builddir
	$(MAKE) -C $(SRC_DIR) all-static
	$(MAKE) -C $(SYSTEMD_DIR)

all-static-musl: mk_builddir
	$(MAKE) -C $(SRC_DIR) all-static-musl
	$(MAKE) -C $(SYSTEMD_DIR)

mk_builddir:
	mkdir -p $(BUILD_DIR)

clean:
	$(MAKE) -C $(SYSTEMD_DIR) clean
	$(MAKE) -C $(SRC_DIR) clean
	rmdir $(BUILD_DIR) 2>/dev/null || /bin/true
	rm -f keepassxc-unlock-*.tar.*

install: mk_builddir
	$(MAKE) -C $(SRC_DIR) install
	$(MAKE) -C $(SYSTEMD_DIR) install

uninstall:
	$(MAKE) -C $(SYSTEMD_DIR) uninstall
	$(MAKE) -C $(SRC_DIR) uninstall

package:
	@make all-static-musl PLATFORMS="$(DEFAULT_PLATFORMS)"
	@for platform in $(DEFAULT_PLATFORMS); do \
		arch="$${platform#linux/}"; \
		package_name=keepassxc-unlock-$${arch}.tar.xz; \
		binaries=$$(compgen -G "$(BUILD_DIR)/keepassxc-*-$${arch}-static"); \
		binary_names=$$(echo "$${binaries}" | xargs -n1 basename); \
		services=$$(compgen -G "$(BUILD_DIR)/*.service"); \
		service_names=$$(echo "$${services}" | xargs -n1 basename); \
		tar -C $(BUILD_DIR) -cvf - $${binary_names} $${service_names} | xz -9 -T0 -c - > $${package_name}; \
		rm -f $${package_name}.sig; \
		gpg --output $${package_name}.sig --detach-sig $${package_name}; \
	done
