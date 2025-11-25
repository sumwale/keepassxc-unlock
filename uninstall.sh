#!/usr/bin/env bash

set -e

fg_green='\033[32m'
fg_orange='\033[33m'
fg_cyan='\033[36m'
fg_reset='\033[00m'

sbin_files=(
    keepassxc-unlock-setup
    keepassxc-login-monitor
    keepassxc-unlock
    keepassxc-unlock-all
)
old_sbin_files=(
    pam-keepassxc-auth
)
old_package='pam-keepassxc'
service_files=(
    keepassxc-login-monitor.service
    keepassxc-unlock@.service
)
config_dir=/etc/keepassxc-unlock

# ensure that system PATHs are always searched first
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin:$PATH"

echo
echo -en "${fg_orange}Uninstall keepassxc-unlock from /usr/local? (y/N) $fg_reset"
set +e
read -r resp < /dev/tty
set -e
if ! [[ "$resp" =~ [Yy] ]]; then
  exit 1
fi

echo -e "${fg_orange}Stopping systemd services and removing the service files$fg_reset"
for unit in $(sudo systemctl show 'keepassxc-unlock@*.service' --property=Id --value --no-pager | grep . | uniq); do
  echo -e "$fg_orange  Stopping service '$unit'$fg_reset"
  sudo systemctl stop "$unit"
done
unit=keepassxc-login-monitor.service
echo -e "$fg_orange  Stopping service '$unit'$fg_reset"
sudo systemctl stop "$unit" || true
echo -e "$fg_orange  Disabling service '$unit'$fg_reset"
sudo systemctl disable "$unit" || true
for file in "${service_files[@]}"; do
  sudo rm -f "/etc/systemd/system/$file"
done
echo -e "${fg_orange}Reloading systemd daemon$fg_reset"
sudo systemctl daemon-reload

echo -e "${fg_orange}Removing executables from /usr/local/sbin$fg_reset"
for file in "${sbin_files[@]}" "${old_sbin_files[@]}"; do
  sudo rm -f "/usr/local/sbin/$file"
done

echo -e "${fg_orange}Removing LICENSE and doc files from /usr/local/share/doc$fg_reset"
sudo rm -rf /usr/local/share/doc/keepassxc-unlock "/usr/local/share/doc/$old_package"

if [[ -d "$config_dir" ]]; then
  echo
  echo -e "${fg_cyan}Should the KeePassXC database configuration in $config_dir be removed?"
  echo -n "Be warned that if you remove it, then all the KeePassXC database passwords registered"
  echo " for all users will be lost and you will have to recover them from memory or elsewhere."
  echo -en "${fg_orange}Really remove /etc/keepassxc-unlock? (type YES in capitals) $fg_reset"
  set +e
  read -r resp < /dev/tty
  set -e
  if [[ "$resp" == YES ]]; then
    echo -e "${fg_orange}Removing /etc/keepassxc-unlock$fg_reset"
    sudo rm -rf /etc/keepassxc-unlock
  fi
fi

echo
echo -e "${fg_green}Uninstalled keepassxc-unlock."
echo -e "$fg_reset"
