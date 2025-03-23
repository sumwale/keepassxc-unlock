#!/bin/sh

set -e

if [ $# -ne 1 ]; then
  echo Usage: $0 GPG-RECIPIENT-NAME
  echo
  echo "Missing GPG recipient name (usually the email address)"
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
