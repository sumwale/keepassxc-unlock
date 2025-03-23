#!/bin/bash

set -e

fg_red='\033[31m'
fg_green='\033[32m'
fg_orange='\033[33m'
fg_cyan='\033[36m'
fg_reset='\033[00m'

sbin_files="keepassxc-unlock-setup pam-keepassxc-auth systemd/keepassxc-unlock"
service_files="systemd/keepassxc-unlock@.service"
doc_files="README.md LICENSE"
base_url="https://github.com/sumwale/pam-keepassxc/blob/main"

# ensure that system PATHs are always searched first
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin:$PATH"

if type -p wget >/dev/null; then
  get_cmd="wget -q -O"
elif type -p curl >/dev/null; then
  get_cmd="curl -fsSL -o"
else
  echo -e "${fg_red}Neither wget nor curl found!$fg_reset"
  exit 1
fi
if ! type -p systemctl >/dev/null; then
  echo -e "${fg_red}No systemctl found$fg_reset"
  exit 1
fi

echo
echo -e "${fg_orange}This will install the latest version of pam-keepassxc in /usr/local"
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
for file in $sbin_files; do
  $get_cmd $tmp_dir/$(basename $file) "$base_url/$file?raw=true"
done
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

echo -e "${fg_cyan}Fetching LICENSE and doc files and installing in /usr/local/share/doc$fg_reset"
for file in $doc_files; do
  $get_cmd $tmp_dir/$(basename $file) "$base_url/$file?raw=true"
done
sudo install -D -t /usr/local/share/doc/pam-keepassxc -m 0644 -o root -g root $tmp_dir/*
rm -f $tmp_dir/*

echo
echo -e "${fg_green}Installation complete."
echo
echo "Run keepassxc-unlock-setup as root to register users' KeePassXC databases to be auto-unlocked"
echo
echo -e "Then add the following to your display manager's PAM configuration /etc/pam.d:$fg_reset"
echo
echo "-auth   optional        pam_exec.so /usr/local/sbin/pam-keepassxc-auth"
echo
echo -en "${fg_green}This line should be placed at the end of other 'auth' lines and includes"
echo -n " in the display manager's configuration. For example, GNOME desktop environments usually"
echo -n " use GDM as the display manager that has PAM configuration named gdm or gdm3 in /etc/pam.d."
echo " Likewise KDE desktop environments usually use SDDM having /etc/pam.d/sddm."
echo
echo "Once done, logout and login, then enjoy auto-unlocking of all registered databases."
echo -e $fg_reset
