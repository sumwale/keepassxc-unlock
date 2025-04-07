SHELL = /bin/sh

CC = gcc
CFLAGS = -Wall -Wextra -Wno-unused-parameter -Wstack-protector -O2 -fstack-protector-all -fstack-protector-strong
DEFINES = -DPRODUCT_VERSION=\"$(PRODUCT_VERSION)\"
INCLUDES := $(shell pkg-config --cflags glib-2.0 gio-2.0 libcrypto)
LDFLAGS = -lgio-2.0 -lgmodule-2.0 -lgobject-2.0 -lglib-2.0 -lcrypto

INSTALL_BIN_DIR = /usr/local/sbin

TARGETS = keepassxc-login-monitor keepassxc-unlock
ARCH := $(shell uname -m)
TARGETS_STATIC := $(patsubst %,%-$(ARCH)-static,$(TARGETS))
PLATFORMS = linux/$(ARCH)
STATIC_LIBS =

.PHONY: all all-static all-static-musl clean install uninstall

all: $(TARGETS)

all-static: $(TARGETS_STATIC)

$(TARGETS): keepassxc-%: %.c common.c common.h
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $^ $(LDFLAGS)

$(TARGETS_STATIC): keepassxc-%-$(ARCH)-static: %.c common.c common.h
	$(CC) -static $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $^ $(LDFLAGS) $(STATIC_LIBS)

all-static-musl:
	@if type docker >/dev/null 2>/dev/null; then \
		container_cmd=docker; \
	else \
		container_cmd=podman; \
	fi; \
	for platform in $(PLATFORMS); do \
		$${container_cmd} run --platform $${platform} --rm -v `pwd`:/build -it alpine:latest /bin/sh /build/make-alpine-musl.sh "$(PRODUCT_VERSION)"; \
	done

clean:
	rm -f $(TARGETS) keepassxc-*-static

install: $(TARGETS)
	install -m 0755 $(TARGETS) $(INSTALL_BIN_DIR)/

uninstall:
	for target in $(TARGETS); do \
		rm -f $(INSTALL_BIN_DIR)/$${target}; \
	done
