.PHONY: all all-static all-static-musl clean install uninstall

SRC_DIR = src
SYSTEMD_DIR = systemd
SETUP = keepassxc-unlock-setup
INSTALL_BIN_DIR = /usr/local/sbin

all:
	$(MAKE) -C $(SRC_DIR)

all-static:
	$(MAKE) -C $(SRC_DIR) all-static

all-static-musl:
	$(MAKE) -C $(SRC_DIR) all-static-musl

clean:
	$(MAKE) -C $(SRC_DIR) clean

install:
	$(MAKE) -C $(SRC_DIR) install
	$(MAKE) -C $(SYSTEMD_DIR) install
	install -m 0755 $(SETUP) $(INSTALL_BIN_DIR)/$(SETUP)

uninstall:
	$(MAKE) -C $(SYSTEMD_DIR) uninstall
	$(MAKE) -C $(SRC_DIR) uninstall
	rm -f $(INSTALL_BIN_DIR)/$(SETUP)
