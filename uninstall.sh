#!/bin/bash

set -e

fg_green='\033[32m'
fg_orange='\033[33m'
fg_cyan='\033[36m'
fg_reset='\033[00m'

PRODUCT_LCASE=keepassxc
PRODUCT_NAME=KeePassXC
if [[ "$1" == "--chipass" ]]; then
  PRODUCT_LCASE=chipass
  PRODUCT_NAME=ChiPass
  shift
fi

sbin_files="
    $PRODUCT_LCASE-unlock-setup
    $PRODUCT_LCASE-login-monitor
    $PRODUCT_LCASE-unlock
    $PRODUCT_LCASE-unlock-all
"
old_sbin_files="
    pam-keepassxc-auth
"
old_package='pam-keepassxc'
service_files="
    $PRODUCT_LCASE-login-monitor.service
    $PRODUCT_LCASE-unlock@.service
"
config_dir=/etc/$PRODUCT_LCASE-unlock

# ensure that system PATHs are always searched first
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin:$PATH"

echo
echo -en "${fg_orange}Uninstall $PRODUCT_LCASE-unlock from /usr/local? (y/N) $fg_reset"
set +e
read -r resp < /dev/tty
set -e
if ! [[ "$resp" =~ [Yy] ]]; then
  exit 1
fi

echo -e "${fg_orange}Stopping systemd services and removing the service files$fg_reset"
for unit in $(sudo systemctl show "$PRODUCT_LCASE-unlock@*.service" --property=Id --value --no-pager | grep . | uniq); do
  echo -e "$fg_orange  Stopping service '$unit'$fg_reset"
  sudo systemctl stop "$unit"
done
unit=$PRODUCT_LCASE-login-monitor.service
echo -e "$fg_orange  Stopping service '$unit'$fg_reset"
sudo systemctl stop "$unit" || true
echo -e "$fg_orange  Disabling service '$unit'$fg_reset"
sudo systemctl disable "$unit" || true
for file in $service_files; do
  sudo rm -f "/etc/systemd/system/$file"
done
echo -e "${fg_orange}Reloading systemd daemon$fg_reset"
sudo systemctl daemon-reload

echo -e "${fg_orange}Removing executables from /usr/local/sbin$fg_reset"
for file in $sbin_files  $old_sbin_files; do
  sudo rm -f "/usr/local/sbin/$file"
done

echo -e "${fg_orange}Removing LICENSE and doc files from /usr/local/share/doc$fg_reset"
sudo rm -rf /usr/local/share/doc/$PRODUCT_LCASE-unlock "/usr/local/share/doc/$old_package"

if [[ -d "$config_dir" ]]; then
  echo
  echo -e "${fg_cyan}Should the $PRODUCT_NAME database configuration in $config_dir be removed?"
  echo -n "Be warned that if you remove it, then all the $PRODUCT_NAME database passwords registered"
  echo " for all users will be lost and you will have to recover them from memory or elsewhere."
  echo -en "${fg_orange}Really remove /etc/$PRODUCT_LCASE-unlock? (type YES in capitals) $fg_reset"
  set +e
  read -r resp < /dev/tty
  set -e
  if [[ "$resp" == YES ]]; then
    echo -e "${fg_orange}Removing /etc/$PRODUCT_LCASE-unlock$fg_reset"
    sudo rm -rf /etc/$PRODUCT_LCASE-unlock
  fi
fi

echo
echo -e "${fg_green}Uninstalled $PRODUCT_LCASE-unlock."
echo -e "$fg_reset"
