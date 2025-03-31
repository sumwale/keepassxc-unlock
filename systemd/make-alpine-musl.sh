#!/bin/sh

set -e

apk add gcc make musl-dev glib-dev glib-static openssl-dev openssl-libs-static zlib-static
apk add coreutils util-linux-static libeconf-dev
apk cache purge

arch=`uname -m`
target=keepassxc-unlock-$arch-static
cd /build
make $target STATIC_LIBS="-lpcre2-8 -lffi -lz -lintl -lmount -lblkid -leconf"
strip -g $target
chown --reference keepassxc-unlock.c $target
