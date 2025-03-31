.PHONY: all clean install uninstall

SUBDIR = systemd
SETUP = keepassxc-unlock-setup

all:
	$(MAKE) -C $(SUBDIR)

static-musl:
	$(MAKE) -C $(SUBDIR) static-musl

install:
	$(MAKE) -C $(SUBDIR) install
	install -m 0755 $(SETUP) /usr/local/sbin/$(SETUP)

uninstall:
	$(MAKE) -C $(SUBDIR) uninstall
	rm -f /usr/local/sbin/$(SETUP)

clean:
	$(MAKE) -C $(SUBDIR) clean
