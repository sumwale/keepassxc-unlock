.PHONY: all all-static all-static-musl clean install uninstall

CC = gcc
CFLAGS = -Wall -Wextra -Wno-unused-parameter -Wstack-protector -O2 -fstack-protector-all -fstack-protector-strong
INCLUDES := $(shell pkg-config --cflags glib-2.0 gio-2.0 libcrypto)
LDFLAGS = -lgio-2.0 -lgmodule-2.0 -lgobject-2.0 -lglib-2.0 -lcrypto
INSTALL_BIN_DIR = /usr/local/sbin

TARGETS = keepassxc-login-monitor keepassxc-unlock
LOGIN_SERVICE = keepassxc-login-monitor.service
SERVICES := $(LOGIN_SERVICE) keepassxc-unlock@.service
ARCH := $(shell uname -m)
TARGETS_STATIC := $(patsubst %,%-$(ARCH)-static,$(TARGETS))
PLATFORMS = linux/$(ARCH)
STATIC_LIBS =

all: $(TARGETS)

all-static: $(TARGETS_STATIC)

%.c: keepassxc-unlock-common.h

$(TARGETS): %: %.c keepassxc-unlock-common.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

$(TARGETS_STATIC): %-$(ARCH)-static: %.c keepassxc-unlock-common.c
	$(CC) -static $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS) $(STATIC_LIBS)

all-static-musl:
	if type docker >/dev/null 2>/dev/null; then \
		container_cmd=docker; \
	else \
		container_cmd=podman; \
	fi; \
	for platform in $(PLATFORMS); do \
		$${container_cmd} run --platform $${platform} --rm -v `pwd`:/build -it alpine:latest /bin/sh /build/make-alpine-musl.sh; \
	done

clean:
	rm -f $(TARGETS) keepassxc-*-static

install: $(TARGETS)
	systemctl stop $(LOGIN_SERVICE) || /bin/true
	install -m 0755 $(TARGETS) $(INSTALL_BIN_DIR)/
	install -m 0644 $(SERVICES) /etc/systemd/system/
	systemctl daemon-reload
	systemctl enable --now $(LOGIN_SERVICE)

uninstall:
	for target in $(TARGETS); do \
		rm -f $(INSTALL_BIN_DIR)/$${target}; \
	done
	for unit in `systemctl -q list-units 'keepassxc-unlock@*.service' | awk '{ print $$1 }'`; do \
		systemctl stop "$$unit"; \
	done
	systemctl stop $(LOGIN_SERVICE) || /bin/true
	systemctl disable $(LOGIN_SERVICE) || /bin/true
	for service in $(SERVICES); do \
		rm -f /etc/systemd/system/$${service}; \
	done
	systemctl daemon-reload
