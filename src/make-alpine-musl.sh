#!/bin/sh

set -e

apk add gcc make coreutils musl-dev glib-dev openssl-dev libeconf-dev
apk add glib-static openssl-libs-static zlib-static util-linux-static
apk cache purge

cd /build
make all-static PRODUCT_VERSION="$1" STATIC_LIBS="-lpcre2-8 -lffi -lz -lintl -lmount -lblkid -leconf"
strip -g *-`uname -m`-static
chown --reference unlock.c *-static
