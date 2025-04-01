.PHONY: all all-static all-static-musl clean install uninstall

SUBDIR = systemd
SETUP = keepassxc-unlock-setup
INSTALL_BIN_DIR = /usr/local/sbin

all:
	$(MAKE) -C $(SUBDIR)

all-static:
	$(MAKE) -C $(SUBDIR) all-static

all-static-musl:
	$(MAKE) -C $(SUBDIR) all-static-musl

clean:
	$(MAKE) -C $(SUBDIR) clean

install:
	$(MAKE) -C $(SUBDIR) install
	install -m 0755 $(SETUP) $(INSTALL_BIN_DIR)/$(SETUP)

uninstall:
	$(MAKE) -C $(SUBDIR) uninstall
	rm -f $(INSTALL_BIN_DIR)/$(SETUP)
