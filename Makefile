SHELL = /bin/bash

SRC_DIR = src
SYSTEMD_DIR = systemd
SETUP = keepassxc-unlock-setup
INSTALL_BIN_DIR = /usr/local/sbin
PRODUCT_VERSION := $(shell bash ./version.sh)
DEFAULT_PLATFORMS = linux/x86_64 linux/aarch64

export PRODUCT_VERSION

.PHONY: $(SETUP) all all-static all-static-musl clean install uninstall package

all: $(SETUP)
	$(MAKE) -C $(SRC_DIR)

all-static: $(SETUP)
	$(MAKE) -C $(SRC_DIR) all-static

all-static-musl: $(SETUP)
	$(MAKE) -C $(SRC_DIR) all-static-musl

$(SETUP): $(SETUP).in
	@echo creating $(SETUP)
	@sed 's/@@PRODUCT_VERSION@@/$(PRODUCT_VERSION)/g' $(SETUP).in > $(SETUP)
	@chmod +x $(SETUP)

clean:
	$(MAKE) -C $(SRC_DIR) clean
	rm -f $(SETUP) keepassxc-unlock-*-$(PRODUCT_VERSION).tar.*

install:
	$(MAKE) -C $(SRC_DIR) install
	$(MAKE) -C $(SYSTEMD_DIR) install
	install -m 0755 $(SETUP) $(INSTALL_BIN_DIR)/$(SETUP)

uninstall:
	$(MAKE) -C $(SYSTEMD_DIR) uninstall
	$(MAKE) -C $(SRC_DIR) uninstall
	rm -f $(INSTALL_BIN_DIR)/$(SETUP)

package:
	@make all-static-musl PLATFORMS="$(DEFAULT_PLATFORMS)"
	@for platform in $(DEFAULT_PLATFORMS); do \
		arch="$${platform#linux/}"; \
		package_name=keepassxc-unlock-$${arch}-$(PRODUCT_VERSION).tar.xz; \
		binaries=$$(compgen -G "$(SRC_DIR)/keepassxc-*-$${arch}-static"); \
		binary_names=$$(echo "$${binaries}" | sed 's/$(SRC_DIR)\///g'); \
		tar -C $(SRC_DIR) -cvf - $${binary_names} | xz -9 -T0 -c - > $${package_name}; \
		rm -f $${package_name}.sig; \
		gpg --output $${package_name}.sig --detach-sig $${package_name}; \
	done
