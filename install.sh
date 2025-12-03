#!/bin/bash

set -e

fg_red='\033[31m'
fg_green='\033[32m'
fg_orange='\033[33m'
fg_cyan='\033[36m'
fg_reset='\033[00m'

src_files="
    src/login-monitor.c
    src/login-monitor-main.c
    src/unlock.c
    src/unlock-main.c
    src/unlock-setup.c
    src/unlock-setup-main.c
    src/common.c
    src/common.h
    src/Makefile
"
service_files="
    systemd/keepassxc-login-monitor.service
    systemd/keepassxc-unlock@.service
"
doc_files="
    README.md
    LICENSE
"
git_site="https://github.com/sumwale/keepassxc-unlock"
base_url="$git_site/blob/main"
base_release_url="$git_site/releases/latest/download"
# GPG key used for signing the release tarballs
gpg_key_id=C9C718FF0C9D3AA4B54E18D93FD1139880CD9DB7

reset_tmp() {
    if [[ -d "$tmp_dir" ]]; then
        rm -rf "$tmp_dir"
    fi
    tmp_dir="$(mktemp -d)"
}

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

if [[ "$EUID" -eq 0 ]]; then
  echo -e "${fg_red}Do not run script as root$fg_reset"
  exit 1
elif ! type -p systemctl >/dev/null; then
  echo -e "${fg_red}No systemctl found$fg_reset - this program expects systemd"
  exit 1
fi

echo
echo -e "${fg_orange}This will install the latest version of keepassxc-unlock in /usr/local"
echo -en "${fg_cyan}Proceed? (Y/n) $fg_reset"
set +e
read -r resp < /dev/tty
set -e
if [[ "$resp" =~ [Nn] ]]; then
  echo -e "${fg_red}Aborting$fg_reset"
  exit 2
fi

reset_tmp

trap "/bin/rm -rf '$tmp_dir'" 0 1 2 3 4 5 6 11 12 15

echo -e "${fg_orange}Stopping login monitor service$fg_reset"
sudo systemctl stop keepassxc-login-monitor.service 2>/dev/null || true
if [[ "$1" == "--build" ]]; then
  echo -e "${fg_cyan}Building the latest git code from source...$fg_reset"
  # first get version.sh
  $get_cmd "$tmp_dir/version.sh" "$base_url/version.sh?raw=true"
  product_version="$(bash "$tmp_dir/version.sh" --remote)"
  rm -f "$tmp_dir/version.sh"
  for file in $src_files; do
    $get_cmd "$tmp_dir/$(basename "$file")" "$base_url/$file?raw=true"
  done
  make -C "$tmp_dir" "PRODUCT_VERSION=$product_version" "BUILD_DIR=$tmp_dir"
  for file in $src_files; do
    rm -f "$tmp_dir/$(basename "$file")"
  done
  find "$tmp_dir" -maxdepth 1 -mindepth 1 -name '*.o' -type f -delete
  echo -e "${fg_orange}Fetching systemd service files$fg_reset"
  for file in $service_files; do
    $get_cmd "$tmp_dir/$(basename "$file")" "$base_url/$file?raw=true"
  done
else
  echo -e "${fg_orange}Fetching tarball having executables and systemd service files$fg_reset"
  # get the latest release tarball removing the commit ID from the product version
  tarball="keepassxc-unlock-$(uname -m).tar.xz"
  $get_cmd "$tmp_dir/$tarball" "$base_release_url/$tarball"
  $get_cmd "$tmp_dir/$tarball.sig" "$base_release_url/$tarball.sig"
  if ! gpg --verify --assert-signer "$gpg_key_id" "$tmp_dir/$tarball.sig" "$tmp_dir/$tarball"; then
    echo
    echo -e "${fg_orange}Signature verification failed for the package"
    echo -en "${fg_cyan}Fetch the public key and try again? (Y/n) $fg_reset"
    set +e
    read -r resp < /dev/tty
    set -e
    if [[ "$resp" =~ [Nn] ]]; then
      echo -e "${fg_red}Aborting installation$fg_reset"
      exit 3
    fi
    gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys "$gpg_key_id"
    gpg --verify --assert-signer "$gpg_key_id" "$tmp_dir/$tarball.sig" "$tmp_dir/$tarball"
  fi
  tar -C "$tmp_dir" -xvf "$tmp_dir/$tarball"
  rm -f "$tmp_dir/$tarball" "$tmp_dir/$tarball.sig"
  static_suffix="-$(uname -m)-static"
  while IFS= read -r -d $'\0' file; do
    chmod 0755 "$file"
    if [[ -L "$file" ]]; then
      target="$(readlink "$file")"
      rm -f "$file"
      ln -s "${target%"$static_suffix"}" "${file%"$static_suffix"}"
    else
      mv "$file" "${file%"$static_suffix"}"
    fi
  done < <(find "$tmp_dir" -maxdepth 1 -mindepth 1 -name "*$static_suffix" -print0)
fi

echo -e "${fg_orange}Installing systemd service files in /etc/systemd/system$fg_reset"
find "$tmp_dir" -maxdepth 1 -mindepth 1 -name '*.service' -type f \
    -exec sudo install -Ct /etc/systemd/system -m 0644 -o root -g root '{}' +
find "$tmp_dir" -maxdepth 1 -mindepth 1 -name '*.service' -type f -delete

echo -e "${fg_orange}Installing binaries in /usr/local/sbin$fg_reset"
find "$tmp_dir" -maxdepth 1 -mindepth 1 -exec \
    sudo install -Ct /usr/local/sbin -m 0750 -o root -g root '{}' +
reset_tmp

echo -e "${fg_orange}Reloading systemd daemon$fg_reset"
sudo systemctl daemon-reload

echo -e "${fg_orange}Enabling and starting login monitor service$fg_reset"
sudo systemctl enable --now keepassxc-login-monitor.service

echo -e "${fg_cyan}Fetching LICENSE and doc files and installing in /usr/local/share/doc$fg_reset"
for file in $doc_files; do
  $get_cmd "$tmp_dir/$(basename "$file")" "$base_url/$file?raw=true"
done
find "$tmp_dir" -maxdepth 1 -mindepth 1 -exec \
    sudo install -CD -t /usr/local/share/doc/keepassxc-unlock -m 0644 -o root -g root '{}' +
reset_tmp

# upgrade obsolete configuration files after user confirmation
while IFS= read -r -d $'\0' old_conf; do
  if [[ "$(basename "$old_conf")" != kdbx-*.conf ]]; then
    echo -en "${fg_orange}Found obsolete configuration '$old_conf'.\nAuto upgrade? (y/N) $fg_reset"
    set +e
    read -r resp < /dev/tty
    set -e
    if [[ "$resp" =~ [Yy] ]]; then
      if sudo /usr/local/sbin/keepassxc-unlock-setup --upgrade "$old_conf"; then
        sudo rm -f "$old_conf"
        echo -e "${fg_orange}Upgraded and removed old configuration '$old_conf'$fg_reset"
      else
        echo -e "${fg_orange}\nFailed to auto-upgrade the old configuration '$old_conf'."
        echo -e "Please remove it manually and register using keepassxc-unlock-setup.$fg_reset"
      fi
    fi
  fi
done < <(sudo find /etc/keepassxc-unlock -maxdepth 2 -mindepth 2 -name '*.conf' -print0)

echo
echo -e "${fg_orange}Start user-specific auto-unlock service? This will only work if"
echo "this is an upgrade and KDBX databases have already been registered using"
echo "keepassxc-unlock-setup previously and KeePassXC is running in the current session."
echo -en "${fg_cyan}Proceed? (y/N) $fg_reset"
set +e
read -r resp < /dev/tty
set -e
if [[ "$resp" =~ [Yy] ]]; then
  # find the session path for this session, write to session.env and start the service
  session_id=$(dbus-send --system --print-reply --type=method_call \
    --dest=org.freedesktop.login1 /org/freedesktop/login1/session/auto \
    org.freedesktop.DBus.Properties.Get string:org.freedesktop.login1.Session string:Id | \
    sed -n 's/.*string "\([0-9]\+\).*/\1/p')
  if [[ -n "$session_id" ]]; then
    session_path=$(dbus-send --system --print-reply --type=method_call \
      --dest=org.freedesktop.login1 /org/freedesktop/login1 \
      org.freedesktop.login1.Manager.GetSession "string:$session_id" | \
      sed -n 's/.*object path "\([^"]*\).*/\1/p')
    if [[ -n "$session_path" ]]; then
      echo "SESSION_PATH=$session_path" | sudo tee "/etc/keepassxc-unlock/$EUID/session.env"
      service_name="keepassxc-unlock@${EUID}.service"
      echo -e "${fg_orange}Starting $service_name$fg_reset"
      sudo systemctl stop "$service_name" 2>/dev/null || true
      sudo systemctl start "$service_name" || true
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
echo -e "$fg_reset"
