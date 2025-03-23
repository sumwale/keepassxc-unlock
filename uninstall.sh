#!/bin/bash

set -e

fg_green='\033[32m'
fg_orange='\033[33m'
fg_cyan='\033[36m'
fg_reset='\033[00m'

sbin_files="keepassxc-unlock-setup pam-keepassxc-auth systemd/keepassxc-unlock"
service_files="systemd/keepassxc-unlock@.service"
doc_files="README.md LICENSE"
config_dir=/etc/keepassxc-unlock

# ensure that system PATHs are always searched first
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin:$PATH"

echo
echo -en "${fg_orange}Uninstall pam-keepassxc from /usr/local? (y/N) $fg_reset"
read -r resp

if [ "$resp" != y -a "$resp" != Y ]; then
  exit 1
fi

echo -e "${fg_orange}Removing executables from /usr/local/sbin$fg_reset"
for file in $sbin_files; do
  sudo rm -f /usr/local/sbin/$(basename $file)
done

echo -e "${fg_orange}Stopping systemd services and removing the service file$fg_reset"
for unit in $(sudo systemctl -q list-units 'keepassxc-unlock@*.service' | awk '{ print $1 }'); do
  echo -e "$fg_orange  Stopping service '$unit'$fg_reset"
  sudo systemctl stop "$unit"
done
for file in $service_files; do
  sudo rm -f /etc/systemd/system/$file
done
echo -e "${fg_orange}Reloading systemd daemon$fg_reset"
sudo systemctl daemon-reload

echo -e "${fg_orange}Removing LICENSE and doc files from /usr/local/share/doc$fg_reset"
sudo rm -rf /usr/local/share/doc/pam-keepassxc

if [ -d $config_dir ]; then
  echo
  echo -e "${fg_cyan}Should the KeePassXC database configuration in $config_dir be removed?"
  echo -n "Be warned that if you remove it, then all the KeePassXC database passwords registered"
  echo " for all users will be lost and you will have to recover them from memory or elsewhere."
  echo -en "${fg_orange}Really remove /etc/keepassxc-unlock? (type YES in capitals) $fg_reset"
  read -r resp
  if [ "$resp" = YES ]; then
    echo -e "${fg_orange}Removing /etc/keepassxc-unlock$fg_reset"
    sudo rm -rf /etc/keepassxc-unlock
  fi
fi

echo
echo -e "${fg_green}Uninstalled pam-keepassxc."
echo -e "Remove the PAM auth directive from your display manager's PAM configuration manually"
echo -e $fg_reset
