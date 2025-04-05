#!/bin/sh

# This script creates a backup of all the registered KDBX databases with their
# passwords encrypted using a given GPG key. You will need to keep the private key
# of the GPG key securely to use it for backup recovery later.
#
# The backup is created in /etc/keepassxc-unlock-backup so users can include this in
# their system backup (while excluding /etc/keepassxc-unlock). The files are encrypted
# individually, so one can decrypt them individually so see the password and key file
# for the KDBX databases for registration on a new system using keepassxc-unlock-setup.

set -e

if [ $# -ne 1 ]; then
  echo Usage: $0 GPG-RECIPIENT-NAME
  echo
  echo "Missing GPG recipient name (usually the email address)"
  exit 1
fi

if [ $(id -u) -ne 0 ]; then
  echo This utility must be run as root
  exit 1
fi

backup_base=/etc/keepassxc-unlock-backup
mkdir -p $backup_base
for dir in /etc/keepassxc-unlock/*; do
  backup_dir=$backup_base/`basename $dir`
  mkdir -p $backup_dir
  for conf in $dir/*; do
    conf_name=`basename $conf .conf`
    { head -3 $conf; tail -n+4 $conf | systemd-creds --name=$conf_name decrypt - -; } | \
      gpg -r "$1" -o - --encrypt - > $backup_dir/$conf_name.gpg
  done
done
