CC = gcc
CFLAGS = -Wall -Wextra -Wno-unused-parameter -Wstack-protector -O2 -fstack-protector
STATIC_LIBS =
LDFLAGS = -lgio-2.0 -lgmodule-2.0 -lgobject-2.0 -lglib-2.0 -lcrypto
TARGET = keepassxc-unlock
SRC = keepassxc-unlock.c

ARCH := $(shell uname -m)
TARGET_STATIC = $(TARGET)-$(ARCH)-static

.PHONY: all static-musl clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) `pkg-config --cflags glib-2.0` -o $(TARGET) $(SRC) $(LDFLAGS)

$(TARGET_STATIC): $(SRC)
	$(CC) -static $(CFLAGS) `pkg-config --cflags glib-2.0` -o $(TARGET_STATIC) $(SRC) $(LDFLAGS) $(STATIC_LIBS)

static-musl:
	if type docker >/dev/null 2>/dev/null; then \
		container_cmd=docker; \
	else \
		container_cmd=podman; \
	fi; \
	$$container_cmd run --rm -v `pwd`:/build -it alpine:latest /bin/sh /build/make-alpine-musl.sh

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/sbin/$(TARGET)

uninstall:
	rm -f /usr/local/sbin/$(TARGET)

clean:
	rm -f $(TARGET) $(TARGET_STATIC)
