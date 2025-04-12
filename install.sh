#!/bin/bash

set -e

fg_red='\033[31m'
fg_green='\033[32m'
fg_orange='\033[33m'
fg_cyan='\033[36m'
fg_reset='\033[00m'

src_files="src/login-monitor.c src/unlock.c src/common.c src/common.h src/Makefile"
service_files="systemd/keepassxc-login-monitor.service systemd/keepassxc-unlock@.service"
doc_files="README.md LICENSE"
git_site="https://github.com/sumwale/keepassxc-unlock"
base_url="$git_site/blob/main"
base_release_url="$git_site/releases/latest/download"
# GPG key used for signing the release tarballs
gpg_key_id=45AA1929F5181FA12E8DC3FBF6F955142B0ED1AC

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
if [ "$1" = "--build" ]; then
  echo -e "${fg_cyan}Building the latest git code from source...$fg_reset"
  # first get version.sh
  $get_cmd $tmp_dir/version.sh "$base_url/version.sh?raw=true"
  product_version=$(bash $tmp_dir/version.sh --remote)
  rm -f $tmp_dir/version.sh
  for file in $src_files; do
    $get_cmd $tmp_dir/$(basename $file) "$base_url/$file?raw=true"
  done
  make -C $tmp_dir "PRODUCT_VERSION=$product_version"
  for file in $src_files; do
    rm -f $tmp_dir/$(basename $file)
  done
else
  # get the latest release tarball removing the commit ID from the product version
  tarball=keepassxc-unlock-$(uname -m).tar.xz
  $get_cmd $tmp_dir/$tarball "$base_release_url/$tarball"
  $get_cmd $tmp_dir/$tarball.sig "$base_release_url/$tarball.sig"
  if ! gpg --verify --assert-signer $gpg_key_id $tmp_dir/$tarball.sig $tmp_dir/$tarball; then
    echo
    echo -e "${fg_orange}Signature verification failed for the package"
    echo -en "${fg_cyan}Fetch the public key and try again? (Y/n) $fg_reset"
    set +e
    read -r resp < /dev/tty
    set -e
    if [ "$resp" = n -o "$resp" = N ]; then
      echo -e "${fg_red}Aborting installation$fg_reset"
      exit 3
    fi
    gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys $gpg_key_id
    gpg --verify --assert-signer $gpg_key_id $tmp_dir/$tarball.sig $tmp_dir/$tarball
  fi
  tar -C $tmp_dir -xvf $tmp_dir/$tarball
  rm -f $tmp_dir/$tarball $tmp_dir/$tarball.sig
  static_suffix="-$(uname -m)-static"
  chmod 0755 $tmp_dir/*$static_suffix
  for file in $tmp_dir/*$static_suffix; do
    if [ -L $file ]; then
      target=$(readlink $file)
      rm -f $file
      ln -s ${target%$static_suffix} ${file%$static_suffix}
    else
      mv $file ${file%$static_suffix}
    fi
  done
fi
for p in $tmp_dir/*; do
  sudo rm -f /usr/local/sbin/`basename $p`
  sudo cp -d --preserve=mode,timestamps $p /usr/local/sbin/
  rm -f $p
done

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

# upgrade obsolete configuration files after user confirmation
old_confs=$(sudo bash -c 'compgen -G /etc/keepassxc-unlock/*/*.conf' || /bin/true)
if [ -n "$old_confs" ]; then
  for old_conf in $old_confs; do
    if [[ $(basename $old_conf) != kdbx-*.conf ]]; then
      echo -en "${fg_orange}Found obsolete configuration '$old_conf'.\nAuto upgrade? (y/N) $fg_reset"
      set +e
      read -r resp < /dev/tty
      set -e
      if [ "$resp" = y -o "$resp" = Y ]; then
        if sudo /usr/local/sbin/keepassxc-unlock-setup --upgrade $old_conf; then
          sudo rm -f $old_conf
          echo -e "${fg_orange}Upgraded and removed old configuration '$old_conf'$fg_reset"
        else
          echo -e "${fg_orange}\nFailed to auto-upgrade the old configuration '$old_conf'."
          echo -e "Please remove it manually and register using keepassxc-unlock-setup.$fg_reset"
        fi
      fi
    fi
  done
fi

echo
echo -e "${fg_orange}Start user-specific auto-unlock service? This will only work if"
echo "this is an upgrade and KDBX databases have already been registered using"
echo "keepassxc-unlock-setup previously and KeePassXC is running in the current session."
echo -en "${fg_cyan}Proceed? (y/N) $fg_reset"
set +e
read -r resp < /dev/tty
set -e
if [ "$resp" = y -o "$resp" = Y ]; then
  # find the session path for this session, write to session.env and start the service
  uid=$(id -u)
  session_id=$(dbus-send --system --print-reply --type=method_call \
    --dest=org.freedesktop.login1 /org/freedesktop/login1/session/auto \
    org.freedesktop.DBus.Properties.Get string:org.freedesktop.login1.Session string:Id | \
    sed -n 's/.*string "\([0-9]\+\).*/\1/p')
  if [ -n "$session_id" ]; then
    session_path=$(dbus-send --system --print-reply --type=method_call \
      --dest=org.freedesktop.login1 /org/freedesktop/login1 \
      org.freedesktop.login1.Manager.GetSession "string:$session_id" | \
      sed -n 's/.*object path "\([^"]*\).*/\1/p')
    if [ -n "$session_path" ]; then
      echo "SESSION_PATH=$session_path" | sudo tee /etc/keepassxc-unlock/$uid/session.env
      service_name=keepassxc-unlock@$uid.service
      echo -e "${fg_orange}Starting $service_name$fg_reset"
      sudo systemctl stop $service_name 2>/dev/null || /bin/true
      sudo systemctl start $service_name || /bin/true
    else
      echo -e "${fg_red}Failed to determine current session's path$fg_reset"
    fi
  fi
fi

echo
echo -e "${fg_green}Installation complete."
echo
echo "Run keepassxc-unlock-setup as root to register users' KeePassXC databases to be auto-unlocked."
echo "Once registered, logout and login, then enjoy auto-unlocking of all registered databases."
echo -e $fg_reset
