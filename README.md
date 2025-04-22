## Introduction

This service for KeePassXC allows full passwordless unlocking of registered KeepassXC
databases after a successful login or screen unlock.

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
about needless complications on the trustworthiness of the other process. In addition,
the SHA512 checksum of the keepassxc executable is verified before making the unlock
D-Bus calls to verify that no other process is listening on.

The global service just starts this user-specific systemd service after a successful
authentication by watching the system D-Bus events, and the service takes over
thereafter watching for the session events on the system D-Bus and invoking for database
unlock (for one or any number of registered databases).

**Doesn't this mean that administrator has full access to all my passwords?**

If the root user or root owned processes are not trusted, then all KeePassXC passwords
are just a gcore+strings command away in any case. That is, the root user can dump the
heap of the keepassxc process and obtain all the passwords in clear text in a matter
of a few minutes. Or the root user can override with a patched version of KeePassXC
that reads and saves the plaintext passwords elsewhere. There are umpteen number of ways
in which the root user or root owned processes can obtain all the passwords even
otherwise, so the scheme does not require any new assumptions beyond the existing trust
model of KeePassXC.

**How good is the encryption of the passwords?**

It uses the exact same scheme as provided by systemd for securing service credentials
which is AES256-GCM + SHA256 (see [systemd-creds man page](https://www.man7.org/linux/man-pages//man1/systemd-creds.1.html)
    for details).

**Will I need to run keepassxc-unlock-setup everytime after an upgrade to KeePassXC?**

It will need to be run for at least one of the user's databases to verify and register
the checksum of the new keepassxc executable. This can be done automatically in future
if this gets integrated into KeePassXC distribution (except if it is running inside
    a containerized environment that can neither update the host's system files
    nor use host's PolicyKit policies).

**Now that I have to never enter the passwords, I will likely forget them**

You should absolutely keep a secure copy of the KeePassXC database passwords elsewhere.
The keys used for encryption are completely device specific and will not work on any
other devices, so a full system backup cannot be used to re-create the passwords
in case the device dies or gets stolen.

To include the passwords as part of a backup, a script can be executed before the
scheduled backup to extract the passwords that can be encrypted with your GPG key
(or equivalent). Of course, a secure backup of this GPG private key will be required.
Let's say you want to decrypt the passwords, then encrypt with the GPG key and store
the files in `/etc/keepassxc-unlock-backup` that can be included in the system backups.
The sh/bash script to do this will look like below (run as root):

```sh
backup_base=/etc/keepassxc-unlock-backup
mkdir -p $backup_base
for dir in /etc/keepassxc-unlock/*; do
  backup_dir=$backup_base/`basename $dir`
  mkdir -p $backup_dir
  for conf in $dir/kdbx-*.conf; do
    conf_name=`basename $conf .conf | sed 's/^kdbx-//'`
    { head -3 $conf; tail -n+4 $conf | systemd-creds --name=$conf_name decrypt - -; } | \
      gpg -r <GPG_ID> -o - --encrypt - > $backup_dir/kdbx-$conf_name.gpg
  done
done
```
(substitute `<GPG_ID>` with the GPG ID to use for encrypting the passwords)

An `examples/backup-gpg.sh` script using the above code is present in the repository.

When restoring on a new system, run `keepassxc-unlock-setup` afresh and decrypt these
individual files to help remember the passwords and key file paths.


## Installation

Install the latest release version using:

```sh
curl -fsSL "https://github.com/sumwale/keepassxc-unlock/blob/main/install.sh?raw=true" | bash
```

OR

```sh
wget -qO- "https://github.com/sumwale/keepassxc-unlock/blob/main/install.sh?raw=true" | bash
```

This will install the binaries in `/usr/local/sbin` and a systemd service file in
`/etc/systemd/system`. The LICENSE and doc files are also installed in
`/usr/local/share/doc/keepassxc-unlock`.

The binaries are statically linked for best compability and will work on all Linux
distributions. The packages on the [releases](https://github.com/sumwale/keepassxc-unlock/releases)
page that are fetched by the install script are signed with a GnuPG key that is verified
before installation.

To uninstall, change `install.sh` in the above commands to `uninstall.sh`.

If you prefer building the binaries from source, then a dynamically linked version can be
built and installed by adding `/dev/stdin --build` at the end of `bash` in the commands above.
This will install the latest version from the git repository:

```sh
curl -fsSL "https://github.com/sumwale/keepassxc-unlock/blob/main/install.sh?raw=true" | bash /dev/stdin --build
```

OR

```sh
wget -qO- "https://github.com/sumwale/keepassxc-unlock/blob/main/install.sh?raw=true" | bash /dev/stdin --build
```

This requires `gcc`, `make`, and development headers for `glibc`, `glib`, `readline`.
As an example, for Debian/Ubuntu based systems, these dependencies can be installed with:
`sudo apt install build-essential libglib2.0-dev libreadline-dev` or on Fedora/RHEL based
systems with: `sudo dnf install gcc make glib2-devel readline-devel`.


## Configuration

Register the KeePassXC databases to be unlocked automatically by running
`keepassxc-unlock-setup`. This has to be run as root user and takes the name
of the user and the path to the KDBX database as two arguments. It will then prompt
the user to enter the key file (if any), and the password.

Run this program for all the databases that need to be automatically unlocked for all
the users. An example run can look like this:

```sh
sudo keepassxc-unlock-setup akash ~akash/keepassxc/passwords.kdbx
...
Enter the password for the database: 
Type the password again: 
Enter the key file for the database (empty for none, use <TAB> for file name completion): 
...

```

The setup will warn if TPM2 support cannot be detected and provide helpful suggestion.
Further it will test these parameters for user confirmation and also register the
keepassxc binary SHA512 checksum which is verified later before auto-unlocking.

That's it. Just logout then login again, and all the KeePassXC databases registered
above will be automatically unlocked, and will continue being unlocked after a screen
lock/unlock, a sleep/wakeup or other such events that may cause KeePassXC to lock
automatically.

### Using custom screen lockers

Normally the screen lock programs shipped with desktop environments will generate
the requisite system D-Bus events that the service is monitoring and will thus be
able to unlock the databases as expected.

However, if a custom screen lock program is being used that does not generate those
events, then KeePassXC itself will not be able to automatically lock the databases
when the screen is locked. For KeePassXC to lock the databases in such a case, explicit
commands to generate D-Bus events to lock the database in the screen locker script
(e.g. using KeePassXC dbus API as shown in the KeePassXC wiki). But this will not help
`keepassxc-unlock` service to unlock the databases automatically on screen unlock.

A better option will be to generate the proper system D-Bus events for the session
in the lock script namely toggling the boolean `LockedHint` property in the object
`/org/freedesktop/login1/session/<session ID>` on the bus `org.freedesktop.login1`.
One way is to use `loginctl lock-session`/`unlock-session`. This way both KeePassXC
and the `keepassxc-unlock` service will be able to lock/unlock the databases correctly.
