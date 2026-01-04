SHELL = /bin/sh

CC = gcc
# CFLAGS and LDFLAGS from:
# https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html
BASE_CFLAGS = -Wall -Wextra -Wno-unused-parameter -Wformat -Wformat=2 -Wconversion \
	      -Wimplicit-fallthrough -Werror=format-security -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
	      -pie -fPIE -fstrict-flex-arrays=3 -fstack-clash-protection -fstack-protector-strong
SANITIZE =
ifeq ($(SANITIZE),)
  CFLAGS = -O2 $(BASE_CFLAGS)
else
  CFLAGS = -fsanitize=address -g3 $(BASE_CFLAGS)
endif

DEFINES = -DPRODUCT_VERSION=\"$(PRODUCT_VERSION)\"
INCLUDES := $(shell pkg-config --cflags glib-2.0 gio-2.0 readline)
LDFLAGS = -Wl,-z,nodlopen -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now \
	  -Wl,--as-needed -Wl,--no-copy-dt-needed-entries
LDLIBS = -lgio-2.0 -lgmodule-2.0 -lgobject-2.0 -lglib-2.0 -lreadline

INSTALL_BIN_DIR = /usr/local/sbin

TARGET_NAMES = keepassxc-login-monitor keepassxc-unlock keepassxc-unlock-setup
TARGETS := $(patsubst %,$(BUILD_DIR)/%,$(TARGET_NAMES))
TARGET_OBJS := $(patsubst keepassxc-%,$(BUILD_DIR)/%.o,$(TARGET_NAMES))
ARCH := $(shell uname -m)
MULTICALL_STATIC = $(BUILD_DIR)/keepassxc-unlock-all-$(ARCH)-static
TARGETS_STATIC := $(patsubst %,%-$(ARCH)-static,$(TARGETS))
PLATFORMS = linux/$(ARCH)
STATIC_LIBS =

.PHONY: all all-static all-static-musl clean install uninstall

all: $(TARGETS)

all-static: $(MULTICALL_STATIC) $(TARGETS_STATIC)

$(BUILD_DIR)/%.o: %.c common.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -c -o $@ $<

$(TARGETS): $(BUILD_DIR)/keepassxc-%: $(BUILD_DIR)/%.o $(BUILD_DIR)/%-main.o $(BUILD_DIR)/common.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

$(MULTICALL_STATIC): $(TARGET_OBJS) $(BUILD_DIR)/common.o $(BUILD_DIR)/multi-call.o
	$(CC) -static $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS) $(STATIC_LIBS)

$(TARGETS_STATIC): $(MULTICALL_STATIC)
	for target in $(TARGETS_STATIC); do \
		rm -f $${target}; \
		ln -s `basename $(MULTICALL_STATIC)` $${target}; \
	done

all-static-musl:
	mkdir -p $(BUILD_DIR)
	@if type docker >/dev/null 2>/dev/null; then \
		container_cmd=docker; \
	else \
		container_cmd=podman; \
	fi; \
	for platform in $(PLATFORMS); do \
		$${container_cmd} run --platform $${platform} --rm -v `pwd`:/keepassxc-unlock/src -v $(BUILD_DIR):/keepassxc-unlock/build -it alpine:latest /bin/sh /keepassxc-unlock/src/make-alpine-musl.sh "$(PRODUCT_VERSION)"; \
		rm -f $(BUILD_DIR)/*.o; \
	done

clean:
	rm -rf $(BUILD_DIR)

install: $(TARGETS)
	install -m 0755 $(TARGETS) $(INSTALL_ROOT)/$(INSTALL_BIN_DIR)/

uninstall:
	for target in $(TARGETS); do \
		rm -f $(INSTALL_ROOT)/$(INSTALL_BIN_DIR)/`basename $${target}`; \
	done
