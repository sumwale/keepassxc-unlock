SRC_DIR = src
SYSTEMD_DIR = systemd
SETUP = keepassxc-unlock-setup
INSTALL_BIN_DIR = /usr/local/sbin
PRODUCT_VERSION := $(shell bash ./version.sh)

export PRODUCT_VERSION

.PHONY: $(SETUP) all all-static all-static-musl clean install uninstall

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
	rm -f $(SETUP)

install:
	$(MAKE) -C $(SRC_DIR) install
	$(MAKE) -C $(SYSTEMD_DIR) install
	install -m 0755 $(SETUP) $(INSTALL_BIN_DIR)/$(SETUP)

uninstall:
	$(MAKE) -C $(SYSTEMD_DIR) uninstall
	$(MAKE) -C $(SRC_DIR) uninstall
	rm -f $(INSTALL_BIN_DIR)/$(SETUP)
