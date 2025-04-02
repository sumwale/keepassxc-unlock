#!/bin/bash

set -e

fg_red='\033[31m'
fg_green='\033[32m'
fg_orange='\033[33m'
fg_cyan='\033[36m'
fg_reset='\033[00m'

sbin_files="keepassxc-unlock-setup"
musl_suffix="-$(uname -m)-static"
musl_files="keepassxc-login-monitor$musl_suffix keepassxc-unlock$musl_suffix"
src_files="systemd/keepassxc-login-monitor.c systemd/keepassxc-unlock.c systemd/keepassxc-unlock-common.c systemd/keepassxc-unlock-common.h systemd/Makefile"
src_out_files="keepassxc-unlock"
service_files="systemd/keepassxc-login-monitor.service systemd/keepassxc-unlock@.service"
doc_files="README.md LICENSE"
base_url="https://github.com/sumwale/keepassxc-unlock/blob/main"
base_release_url="https://github.com/sumwale/keepassxc-unlock/releases/latest/download"

# ensure that system PATHs are always searched first
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin:$PATH"

if type -p curl >/dev/null; then
  get_cmd="curl -fsSL -o"
elif type -p wget >/dev/null; then
  get_cmd="wget -q -O"
else
  echo -e "${fg_red}Neither curl nor wget found!$fg_reset"
  exit 1
fi
if ! type -p systemctl >/dev/null; then
  echo -e "${fg_red}No systemctl found$fg_reset"
  exit 1
fi

echo
echo -e "${fg_orange}This will install the latest version of keepassxc-unlock in /usr/local"
echo -en "${fg_cyan}Proceed? (Y/n) $fg_reset"
set +e
read -r resp < /dev/tty
set -e
if [ "$resp" = n -o "$resp" = N ]; then
  echo -e "${fg_red}Aborting$fg_reset"
  exit 2
fi

tmp_dir=$(mktemp -d)

trap "/bin/rm -rf $tmp_dir" 0 1 2 3 4 5 6 11 12 15

echo -e "${fg_orange}Fetching executables and installing in /usr/local/sbin$fg_reset"
sudo systemctl stop keepassxc-login-monitor.service 2>/dev/null || /bin/true
for file in $sbin_files; do
  $get_cmd $tmp_dir/$(basename $file) "$base_url/$file?raw=true"
done
if [ "$1" = "--build" ]; then
  echo -e "${fg_cyan}Building from source...$fg_reset"
  for file in $src_files; do
    $get_cmd $tmp_dir/$(basename $file) "$base_url/$file?raw=true"
  done
  make -C $tmp_dir
  for file in $src_files; do
    rm -f $tmp_dir/$(basename $file)
  done
else
  for file in $musl_files; do
    $get_cmd $tmp_dir/$(echo $file | sed "s/$musl_suffix//") "$base_release_url/$file"
  done
fi
sudo install -t /usr/local/sbin -m 0755 -o root -g root $tmp_dir/*
rm -f $tmp_dir/*

echo -e "${fg_orange}Fetching systemd service file and installing in /etc/systemd/system$fg_reset"
for file in $service_files; do
  $get_cmd $tmp_dir/$(basename $file) "$base_url/$file?raw=true"
done
sudo install -t /etc/systemd/system -m 0644 -o root -g root $tmp_dir/*
rm -f $tmp_dir/*

echo -e "${fg_orange}Reloading systemd daemon$fg_reset"
sudo systemctl daemon-reload

echo -e "${fg_orange}Enabling and starting login monitor service$fg_reset"
sudo systemctl enable keepassxc-login-monitor.service
sudo systemctl start keepassxc-login-monitor.service

echo -e "${fg_cyan}Fetching LICENSE and doc files and installing in /usr/local/share/doc$fg_reset"
for file in $doc_files; do
  $get_cmd $tmp_dir/$(basename $file) "$base_url/$file?raw=true"
done
sudo install -D -t /usr/local/share/doc/keepassxc-unlock -m 0644 -o root -g root $tmp_dir/*
rm -f $tmp_dir/*

echo
echo -e "${fg_green}Installation complete."
echo
echo "Run keepassxc-unlock-setup as root to register users' KeePassXC databases to be auto-unlocked."
echo "Once registered, logout and login, then enjoy auto-unlocking of all registered databases."
echo -e $fg_reset
