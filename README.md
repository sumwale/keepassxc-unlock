## Introduction

This PAM module for KeePassXC allows full passwordless unlocking of registered KeepassXC
databases after a successful PAM authentication.

Unlike all other solutions, the password does not have to have any relation to the
login password of the user. In fact the user may not even be using password for login
(e.g. using fingerprint or any other PAM authentication scheme). In addition this
module can automatically unlock any number of KeepassXC databases and not just a single
"primary" one.

The scheme is secure as long as the root user and root owned processes are trusted.


## How does it work?

The general idea is that the passwords are registered with the system and encrypted
by the root user using the same mechanism as the standard [systemd service credentials](
https://systemd.io/CREDENTIALS). The `systemd-creds` utility provides the encryption and
decryption facility using a combination of locally stored system key and a key in TPM2
(if available).

The second important idea is that all the database unlock operations are carried out by
a root owned systemd service itself and not by any other user process that can bring
about needless complications on the trustworthiness of the other process.

The PAM module itself just starts this user-specific systemd service after a successful
authentication by other modules, and the service takes over thereafter watching for the
session events on the system D-BUS and invoking for database unlock (for one or any
    number of registered databases).

**Doesn't this mean that administrator has full access to all my passwords?**

If the root user or root owned processes are not trusted, then all KeePassXC passwords
are just a gcore+strings command away in any case. That is the root user can dump the
heap of the keepassxc process and obtain all the passwords in clear text in a matter
of a few minutes. So the scheme does not require any new assumptions beyond the existing
trust model of keepassxc.

**How good is the encryption of the passwords?**

It uses the exact same scheme as provided by systemd for securing service credentials
which is AES256-GCM + SHA256 (see [systemd-creds man page](https://www.man7.org/linux/man-pages//man1/systemd-creds.1.html)
    for details).

**Now that I have to never enter the passwords, I will likely forget the passwords**

You should absolutely keep a secure copy of the KeePassXC database passwords elsewhere.
The keys used for encryption are completely device specific and will not work on any
other devices, so you cannot rely on a full system backup to re-create the passwords
in case your device dies or gets stolen.

If you want to include the passwords as part of your backup then you can run a script
before your scheduled backup to extract the passwords and encrypt with your GPG key (or
equivalent). Of course, you will need a secure backup of your GPG private key.
Let's say you want to decrypt the passwords, then encrypt with your GPG key and store
the files in `/etc/keepassxc-unlock-backup` that can be included in your system backups.
The script to do this will look like below (run as root):

```sh
backup_base=/etc/keepassxc-unlock-backup
mkdir -p $backup_base
for dir in /etc/keepassxc-unlock/*; do
  backup_dir=$backup_base/`basename $dir`
  mkdir -p $backup_dir
  for conf in $dir/*; do
    conf_name=`basename $conf .conf`
    { head -3 $conf; tail -n+4 $conf | systemd-creds --name=$conf_name decrypt - -; } | \
      gpg -r <GPG_ID> -o - --encrypt - > $backup_dir/$conf_name.gpg
  done
done
```
(substitute `<GPG_ID>` with the GPG ID you will use for encrypting the passwords)

An `examples/backup-gpg.sh` script using the above code is present in the repository.

When restoring on a new system, you can decrypt these individual files to help remember
the passwords and key file paths when running the `keepassxc-unlock-setup` utility on
the new system.


## WARNING

This initial implementation just uses bash scripts and can briefly expose the password
in the command-line of `dbus-send` command. However, the implementation itself is quite
well tested, so go ahead and start using it if you are not worried about someone or
a malware grabbing the password in that brief window.

The upcoming version in C (or maybe Rust?) will fix this known issue with the current
version of the scripts.


## Installation

Latest version:

```sh
wget -qO- "https://github.com/sumwale/pam-keepassxc/blob/main/install.sh?raw=true" | bash
```

Or,

```sh
curl -fsSL "https://github.com/sumwale/pam-keepassxc/blob/main/install.sh?raw=true" | bash
```

This will install the binaries in `/usr/local/sbin` and a systemd service file in
`/etc/systemd/system`. The LICENSE and doc files are also installed in
`/usr/local/share/doc/pam-keepassxc`.

If you wish to uninstall, then change `install.sh` in the above commands to `uninstall.sh`.


## Configuration

The comments shown at the end the install script mention the required configuration.

First register the KeePassXC databases to be unlocked automatically by running the
`keepassxc-unlock-setup` script. This has to be run as root user and takes then name
of the user and the path to the KDBX database as two arguments. It will then prompt
the user to enter the key file (if any), and the password.

Run this script for all the databases that need to be automatically unlocked for all
the users.

Then add the line below to your display manager's PAM configuration after all other `auth` lines:

```
-auth   optional        pam_exec.so /usr/local/sbin/pam-keepassxc-auth
```

For instance on a Ubuntu system with SDDM, the `/etc/pam.d/sddm` looks like below after
the above change:

```
...
@include common-auth
-auth   optional        pam_kwallet5.so
-auth   optional        pam_exec.so /usr/local/sbin/pam-keepassxc-auth

@include common-account
...

```

That's it. When you logout and then login back, all the KeePassXC databases registered
above will be automatically unlocked, and will continue being unlocked after a screen
lock/unlock, a sleep/wakeup or other such events that may cause KeePassXC to lock
automatically.

### Using custom screen lockers

Normally the screen lock programs shipped with desktop environments will generate
the requisite system D-BUS events that the service is monitoring and will thus be
able to unlock the databases as expected.

However, if you are using a custom screen lock program that does not generate those
events, then KeePassXC itself will normally not be able to automatically lock the
databases when the screen is locked. You will have to add explicit commands to generate
D-BUS events to lock the database in the screen locker script (e.g. using qdbus API as
    shown in KeePassXC wiki).

A better option will be to generate the proper system D-BUS events instead for your
session in the script namely the boolean `LockedHint` property in the object
`/org/freedesktop/login1/session/<session ID>` on the bus `org.freedesktop.login1`.
This way both KeePassXC and the `keepassxc-unlock` service will be able to lock/unlock
the databases correctly.
