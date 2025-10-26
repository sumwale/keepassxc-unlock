#!/bin/sh

set -e

apk update
apk upgrade
apk add gcc make coreutils musl-dev glib-dev readline-dev libeconf-dev
apk add glib-static readline-static ncurses-static zlib-static util-linux-static pcre2-static
apk cache purge

build_dir=../build
cd /keepassxc-unlock/src
make all-static BUILD_DIR=$build_dir PRODUCT_VERSION="$1" STATIC_LIBS="-ltinfo -lpcre2-8 -lffi -lz -lintl -lmount -lblkid -leconf"
strip -g $build_dir/*-all-`uname -m`-static
chown --no-dereference --reference unlock.c $build_dir/*-static
