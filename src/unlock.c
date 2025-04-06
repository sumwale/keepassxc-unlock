#include <fcntl.h>
#include <glib.h>
#include <glob.h>
#include <openssl/evp.h>
#include <pwd.h>
#include <sys/types.h>

#include "common.h"

#define SHA512_BUFFER_SIZE EVP_MAX_MD_SIZE * 2 + 1
#define MAX_PASSWORD_SIZE 4096    // maximum allowed size of decrypted password plus one for null
#define KP_DBUS_INTERFACE "org.keepassxc.KeePassXC.MainWindow"


/// @brief Holds information of the session being monitored and passed to the `user_data` parameter
///        of the `handle_session_event` and `handle_session_close` callbacks. Also passed to the
///        main `unlock_databases` method.
typedef struct {
  GMainLoop *loop;              // the main loop object pointer
  const gchar *session_path;    // path of the selected session
  uid_t user_id;                // numeric ID of the user
  bool is_wayland;              // `true` if the session is a Wayland one, `false` for X11
  const gchar *display;         // the `Display` property of the session
  bool session_locked;          // holds the previous locked state of the session
  bool session_active;          // holds the previous active state of the session
  guint kp_subscription_id;     // the subscription ID of KeePassXC `NameOwnerChanged` signals
} MonitoredSession;


/// @brief Show usage of this program
/// @param script_name name of the invoking script as obtained from `argv[0]`
void show_usage(const char *script_name) {
  printf("\nUsage: %s <USER>\n", script_name);
  printf("\nMonitor a session for login and screen unlock events to unlock configured KeepassXC "
         "databases\n");
  printf("\nArguments:\n");
  printf("  <USER_ID>       numeric ID of user who owns the session to be monitored\n\n");
  printf("  <SESSION_ID>    the session ID to be monitored\n\n");
  fflush(stdout);
}

/// @brief Check if given session is locked (i.e. `LockedHint` is true)
/// @param connection the `GBusConnection` object for the system D-Bus
/// @param session_path path of the selected session
/// @return boolean `LockedHint` property of the session
bool is_locked(GDBusConnection *connection, const char *session_path) {
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) result = g_dbus_connection_call_sync(connection, LOGIN_OBJECT_NAME,
      session_path, DBUS_MAIN_OBJECT_NAME ".Properties", "Get",
      g_variant_new("(ss)", "org.freedesktop.login1.Session", "LockedHint"), NULL,
      G_DBUS_CALL_FLAGS_NONE, DBUS_CALL_WAIT, NULL, &error);
  if (!result) {
    print_error("Failed to get LockedHint: %s\n", error ? error->message : "(null)");
    return true;
  }

  // extract boolean value wrapped inside the variant
  g_autoptr(GVariant) locked_variant = NULL;
  g_variant_get(result, "(v)", &locked_variant);
  return g_variant_get_boolean(locked_variant);
}

/// @brief Change the effective user ID to the given one with error checking.
///        Exit the whole program with code 1 if it fails to change effective UID back to 0.
/// @param uid the user ID to be set as the effective UID
void change_euid(uid_t uid) {
  if (geteuid() == uid) return;
  if (seteuid(uid) != 0) {
    print_error("\033[1;33mchange_euid() failed in seteuid to %u: \033[00m", uid);
    perror(NULL);
    if (uid == 0) {    // failed to switch back to root?
      print_error("\033[1;31mCannot switch back to root, terminating...\033[00m\n");
      exit(1);
    }
  }
}

/// @brief Connect to the user's session D-Bus while switching effective user ID. Optionally display
///        error on `stderr` if there was a connection failure.
/// @param user_id the numeric ID of the user to switch the effective user ID for session connect to
///                be successful; the effective user ID will be switched back to root at the end
/// @param log_error if `true` then log connection error to `stderr`
/// @return an instance of `GDBusConnection*` that may be shared among callers and must be released
///         using `g_object_unref()`/`g_autoptr()`, or NULL if the connection was unsuccessful
GDBusConnection *dbus_session_connect(uid_t user_id, bool log_error) {
  change_euid(user_id);
  GDBusConnection *session_conn = dbus_connect(false, log_error);
  change_euid(0);
  return session_conn;
}

/// @brief Get the process ID registered for given D-Bus API on the session bus.
///        Since this uses the session bus, the call should be done after changing
///        the effective UID of this process to the target user.
/// @param dbus_api the D-Bus API that the process has registered
/// @param user_id numeric ID of the user
/// @param log_error if `true` then log D-Bus connection error to `stderr`
/// @return the process ID registered for the D-Bus API or 0 if something went wrong
guint32 get_dbus_service_process_id(const char *dbus_api, uid_t user_id, bool log_error) {
  g_autoptr(GDBusConnection) session_conn = dbus_session_connect(user_id, log_error);
  if (!session_conn) return 0;

  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) result = g_dbus_connection_call_sync(session_conn, "org.freedesktop.DBus",
      "/", DBUS_MAIN_OBJECT_NAME, "GetConnectionUnixProcessID", g_variant_new("(s)", dbus_api),
      NULL, G_DBUS_CALL_FLAGS_NONE, DBUS_CALL_WAIT, NULL, &error);
  if (result) {
    guint32 pid = 0;
    g_variant_get(result, "(u)", &pid);
    return pid;
  } else {
    return 0;
  }
}

/// @brief Calculate the SHA-512 hash for the given file and return as a hexadecimal
///        string in the given buffer.
/// @param path path of the file for which SHA-512 hash has to be calculated
/// @param hash_buffer fill the SHA-512 hash as a hexadecimal string with terminating null
/// @param buffer_size total size of the passed `hash_buffer`
/// @return length of the filled `hash_buffer` excluding terminating null, else 0 in case of failure
///         or if the buffer is not large enough
size_t sha512sum(const char *path, char *hash_buffer, size_t buffer_size) {
  int fd = open(path, O_RDONLY);
  if (fd == -1) {
    perror("sha512sum() failed to open file");
    return 0;
  }

  // read data from the file in chunks and keep updating the checksum
  unsigned char buffer[32768];
  ssize_t bytes_read;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;
  // keep on heap to maintain compatibility in the case of change in size of EVP_MD_CTX struct
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(md_ctx, EVP_sha512(), NULL);
  while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
    EVP_DigestUpdate(md_ctx, buffer, bytes_read);
  }
  if (bytes_read == -1) {
    perror("sha512sum() failed to read file");
  } else {
    EVP_DigestFinal_ex(md_ctx, hash, &hash_len);
  }
  close(fd);
  EVP_MD_CTX_free(md_ctx);
  if (bytes_read == -1) return 0;

  // convert bytes to hex string using sprintf which is not efficient but its a tiny fixed overhead
  size_t buf_len = 0;
  for (size_t i = 0; i < hash_len; i++, buf_len += 2) {
    if (buf_len >= buffer_size - 2) return 0;
    sprintf(hash_buffer + buf_len, "%02x", hash[i]);
  }
  hash_buffer[buf_len] = '\0';
  return buf_len;
}

/// @brief Send a notification to the desktop using the D-Bus `org.freedesktop.Notifications` API
///        (like that done by `libnotify`/`notify-send`).
/// @param user_id numeric ID of the user
/// @param name application name for the notification
/// @param icon icon filename or stock icon to display
/// @param summary summary of the notification message
/// @param body body of the notification message
/// @param urgency the urgency level of the notification (0 - low, 1 - normal, 2 - critical)
/// @param timeout duration, in milliseconds, for the notification to appear on screen
/// @return `true` if the notification was relayed successfully, `false` otherwise
bool send_session_notification(uid_t user_id, const gchar *name, const gchar *icon,
    const gchar *summary, const gchar *body, guint8 urgency, gint32 timeout) {
  g_autoptr(GDBusConnection) session_conn = dbus_session_connect(user_id, true);
  if (!session_conn) return 0;

  g_auto(GVariantBuilder) hints;
  g_variant_builder_init(&hints, G_VARIANT_TYPE_VARDICT);
  g_variant_builder_add(&hints, "{sv}", "urgency", g_variant_new_byte(urgency));
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) result =
      g_dbus_connection_call_sync(session_conn, "org.freedesktop.Notifications",
          "/org/freedesktop/Notifications", "org.freedesktop.Notifications", "Notify",
          g_variant_new("(susssasa{sv}i)", name, 0, icon, summary, body, NULL, &hints, timeout),
          NULL, G_DBUS_CALL_FLAGS_NONE, DBUS_CALL_WAIT, NULL, &error);
  return result ? true : false;
}

/// @brief Verify that the KeePassXC process belongs to the selected session. This is done by
///        comparing the $DISPLAY variable of the process with the `Display` property of the session
///        for X11, or checking that $WAYLAND_DISPLAY is non-empty for Wayland.
/// @param kp_pid process ID of KeePassXC
/// @param is_wayland `true` if the session is a Wayland one, else `false` if it is X11
/// @param display the $DISPLAY variable for the session as retrieved from its `Display` property
/// @return `true` if the KeePassXC is running in the session else `false`
bool verify_process_session(guint32 kp_pid, bool is_wayland, const gchar *display) {
  if (is_wayland) {
    // the `Display` property of the session is not set for the case of Wayland, and there is no way
    // to check if this is the same Wayland session (multiple Wayland sessions break stuff in many
    //   ways in any case) so just check that $WAYLAND_DISPLAY is not non-empty
    g_autofree gchar *env_value = get_process_env_var(kp_pid, "WAYLAND_DISPLAY");
    return env_value && *env_value != '\0';
  } else {
    // for the case of X11, the value of $DISPLAY should match the passed `Display` session property
    g_autofree gchar *env_value = get_process_env_var(kp_pid, "DISPLAY");
    return g_strcmp0(env_value, display) == 0;
  }
}

/// @brief Get the executable's SHA-512 hash from /proc/<pid>/exe and compare against the recorded
///        good checksum.
/// @param user_id numeric ID of the user
/// @param kp_pid process ID of KeePassXC
/// @return `true` if the checksum matched else `false`
bool verify_process_exe_sha512(const char *user_conf_dir, uid_t user_id, guint32 kp_pid) {
  // get the executable's SHA-512 hash from /proc/<pid>/exe and compare against the
  // recorded good checksum
  char expected_sha512[SHA512_BUFFER_SIZE], current_sha512[SHA512_BUFFER_SIZE];
  char kp_sha512_file[128], kp_exe[128];
  snprintf(kp_sha512_file, sizeof(kp_sha512_file), "%s/keepassxc.sha512", user_conf_dir);
  FILE *file = fopen(kp_sha512_file, "r");
  if (!file) {
    print_error(
        "Skipping unlock due to missing %s - run 'sudo keepassxc-unlock-setup'\n", kp_sha512_file);
    return false;
  }
  snprintf(kp_exe, sizeof(kp_exe), "/proc/%u/exe", kp_pid);
  bool mismatch = sha512sum(kp_exe, current_sha512, SHA512_BUFFER_SIZE) == 0;
  // use `fgets` to read the sha512 file which is expected to have only one line
  // and replace terminating newline using `strcspn` (which works even if there was no newline)
  mismatch = mismatch || !fgets(expected_sha512, sizeof(expected_sha512), file) ||
             (expected_sha512[strcspn(expected_sha512, "\n")] = '\0',
                 g_strcmp0(current_sha512, expected_sha512) != 0);
  fclose(file);
  if (mismatch) {
    // `kp_exe_full` stores the actual executable that /proc/<pid>/exe points to, while
    // `kp_exe_real` will either point to it or /proc/<pid>/exe in case `readlink` was unsuccessful
    char kp_exe_full[PATH_MAX], *kp_exe_real = kp_exe;
    ssize_t kp_full_len = readlink(kp_exe, kp_exe_full, sizeof(kp_exe_full) - 1);
    if (kp_full_len > 0) {
      kp_exe_full[kp_full_len] = '\0';
      kp_exe_real = kp_exe_full;
    }
    g_critical("Aborting unlock due to checksum mismatch in keepassxc (PID %u EXE %s)", kp_pid,
        kp_exe_real);
    char notify_body[PATH_MAX * 2];
    snprintf(notify_body, sizeof(notify_body),
        "If KeePassXC has been updated, then run \"sudo keepassxc-unlock-setup ...\" for one of "
        "the KDBX databases.\nOtherwise this could be an unknown process snooping on D-Bus.\n\n "
        "The offending process ID is %u having executable pointing to %s",
        kp_pid, kp_exe_real);
    if (!send_session_notification(user_id, "keepassxc-unlock", "system-lock-screen",
            "Checksum mismatch in keepassxc", notify_body, 2, 120000)) {
      g_critical("Failed to send D-Bus notification to the user for SHA-512 mismatch");
    }
    return false;
  }
  return true;
}

/// @brief Unlock all the KDBX databases that were registered (using `keepassxc-unlock-setup`)
///        of the given user using KeePassXC's D-Bus API.
/// @param system_conn the `GBusConnection` object for the system D-Bus
/// @param session_data instance of `MonitoredSession` struct having information of the session
///                     being monitored
/// @param wait_secs seconds to try connecting to the KeePassXC D-Bus service before giving up
/// @return `true` if connection was successful and unlock was attempted (though one or more
///         databases may have failed to unlock due to other reasons), and `false` if connection to
///         KeePassXC failed or session was still locked
bool unlock_databases(
    GDBusConnection *system_conn, const MonitoredSession *session_data, int wait_secs) {
  if (!session_data) g_error("unlock_databases() null session_data!");

  // loop till `wait_secs` to get the ID of the process providing KeePassXC's D-Bus API
  guint32 kp_pid = 0;
  for (int i = 0; i < wait_secs; i++) {
    // switch effective ID to the user before connecting since this is the user's session bus
    // log connection error only in the last iteration
    kp_pid =
        get_dbus_service_process_id(KP_DBUS_INTERFACE, session_data->user_id, i == wait_secs - 1);
    if (kp_pid != 0) break;
    sleep(1);
  }
  if (kp_pid == 0) {
    print_error("Failed to connect to KeePassXC D-Bus API within %d secs\n", wait_secs);
    return false;
  }

  // verify from the KeePassXC executable's environment that it is running in the selected session
  if (!verify_process_session(kp_pid, session_data->is_wayland, session_data->display)) {
    print_error("Skipping unlock due to mismatch of $DISPLAY/$WAYLAND_DISPLAY of KeePassXC process "
                "with ID %u against the session properties\n",
        kp_pid);
    return false;
  }

  // verify the KeePassXC executable's checksum
  char user_conf_dir[100];
  snprintf(user_conf_dir, sizeof(user_conf_dir), "%s/%u", KP_CONFIG_DIR, session_data->user_id);
  if (!verify_process_exe_sha512(user_conf_dir, session_data->user_id, kp_pid)) return false;

  // last minute check to skip unlock if LockedHint is true
  if (is_locked(system_conn, session_data->session_path)) {
    print_error("Skipping unlock since screen/session is still locked!\n");
    return false;
  }

  char conf_pattern[128], decrypted_passwd[MAX_PASSWORD_SIZE];
  snprintf(conf_pattern, sizeof(conf_pattern), "%s/*.conf", user_conf_dir);
  glob_t globbuf;
  if (glob(conf_pattern, 0, NULL, &globbuf) == 0) {
    // clear decrypted_passwd in every loop even if the loop condition fails
    for (size_t i = 0; memset(decrypted_passwd, 0, MAX_PASSWORD_SIZE), i < globbuf.gl_pathc; i++) {
      char *conf_path = globbuf.gl_pathv[i];
      FILE *file = fopen(conf_path, "r");
      if (!file) {
        print_error("Failed to open configuration file: %s\n", conf_path);
        continue;
      }

      char line[PATH_MAX];
      char kdbx_file[PATH_MAX] = {0};
      char key_file[PATH_MAX] = {0};
      int passwd_start_line = 0;
      while (fgets(line, sizeof(line), file)) {
        passwd_start_line++;
        if (strncmp(line, "DB=", 3) == 0) {
          strncpy(kdbx_file, line + 3, sizeof(kdbx_file) - 1);
          kdbx_file[strcspn(kdbx_file, "\n")] = '\0';
        } else if (strncmp(line, "KEY=", 4) == 0) {
          strncpy(key_file, line + 4, sizeof(key_file) - 1);
          key_file[strcspn(key_file, "\n")] = '\0';
        } else if (strncmp(line, "PASSWORD:", 9) != 0) {
          // password starts after the line having PASSWORD:
          break;
        }
      }
      fclose(file);

      if (*kdbx_file == '\0') {
        print_error("Skipping invalid KDBX unlock configuration file '%s'\n", conf_path);
        continue;
      }

      // check for session end before unlocking
      if (!g_main_loop_is_running(session_data->loop)) {
        print_info("unlock_databases() aborting unlock due to session end");
        break;
      }

      char conf_name[128] = {0}, decrypt_cmd[256];
      char *conf_name_p, *conf_filename = strrchr(conf_path, '/');
      if (conf_filename && (conf_name_p = strstr(conf_filename + 1, ".conf")) != NULL) {
        size_t conf_name_len = conf_name_p - conf_filename - 1;
        strncpy(conf_name, conf_filename + 1, MIN(conf_name_len, sizeof(conf_name)));
      }
      snprintf(decrypt_cmd, sizeof(decrypt_cmd),
          "tail '-n+%d' '%s' | systemd-creds '--name=%s' decrypt - -", passwd_start_line, conf_path,
          conf_name);
      FILE *pipe = popen(decrypt_cmd, "r");
      if (!pipe) {
        perror("Failed to run systemd-creds for decryption");
        continue;
      }
      size_t bytes_read = fread(decrypted_passwd, 1, MAX_PASSWORD_SIZE, pipe);
      pclose(pipe);
      if (bytes_read == MAX_PASSWORD_SIZE) {
        print_error("Password for '%s' exceeds %u characters!\n", kdbx_file, MAX_PASSWORD_SIZE - 1);
        continue;
      }
      decrypted_passwd[bytes_read] = '\0';

      g_autoptr(GDBusConnection) session_conn = dbus_session_connect(session_data->user_id, true);
      if (!session_conn) continue;

      g_autoptr(GError) error = NULL;
      g_autoptr(GVariant) result = g_dbus_connection_call_sync(session_conn, KP_DBUS_INTERFACE,
          "/keepassxc", KP_DBUS_INTERFACE, "openDatabase",
          g_variant_new("(sss)", kdbx_file, decrypted_passwd, key_file), NULL,
          G_DBUS_CALL_FLAGS_NONE, DBUS_CALL_WAIT, NULL, &error);
      if (!result) {
        print_error(
            "Failed to unlock database '%s': %s\n", kdbx_file, error ? error->message : "(null)");
      }
    }
  }
  globfree(&globbuf);
  return true;
}

/// @brief Callback to handle session signals on `org.freedesktop.login1` for selected session
/// @param conn the `GBusConnection` object for the system D-Bus
/// @param sender_name name of the sender of the signal
/// @param object_path path of the object for which the signal was raised
/// @param interface_name D-Bus interface of the raised signal
/// @param signal_name name of the D-Bus signal that was raised
/// @param parameters parameters of the raised signal
/// @param user_data custom user data sent through with the signal which should be pointer to
///                  `MonitoredSession`
void handle_session_event(GDBusConnection *conn, const char *sender_name, const char *object_path,
    const char *interface_name, const char *signal_name, GVariant *parameters, gpointer user_data) {
  MonitoredSession *session_data = (MonitoredSession *)user_data;
  g_autoptr(GVariantIter) iter = NULL;
  const char *key;
  GVariant *value = NULL;
  g_variant_get(parameters, "(sa{sv}as)", NULL, &iter, NULL);
  while (g_variant_iter_loop(iter, "{&sv}", &key, &value)) {
    if (g_strcmp0(key, "LockedHint") == 0) {
      bool locked = g_variant_get_boolean(value);
      if (!locked && session_data->session_locked) {
        print_info("Unlocking database(s) after screen/session unlock event\n");
        unlock_databases(conn, session_data, 5);
      }
      session_data->session_locked = locked;
    } else if (g_strcmp0(key, "Active") == 0) {
      bool active = g_variant_get_boolean(value);
      if (active && !session_data->session_active && !session_data->session_locked) {
        print_info("Unlocking database(s) after session activation event\n");
        unlock_databases(conn, session_data, 5);
      }
      session_data->session_active = active;
    }
  }
}

/// @brief Callback to handle session close for the selected session
void handle_session_close(GDBusConnection *conn, const char *sender_name, const char *object_path,
    const char *interface_name, const char *signal_name, GVariant *parameters, gpointer user_data) {
  MonitoredSession *session_data = (MonitoredSession *)user_data;
  gchar *removed_session_path = NULL;
  g_variant_get(parameters, "(s&o)", NULL, &removed_session_path);    // `&o` avoids `g_free()`
  if (g_strcmp0(removed_session_path, session_data->session_path) == 0) {
    print_info("Exit on session end for %s\n", session_data->session_path);
    g_main_loop_quit(session_data->loop);
  }
}

/// @brief Callback to handle KeePassXC startup when it was not present at the start of this process
void handle_keepassxc_start(GDBusConnection *session_conn, const char *sender_name,
    const char *object_path, const char *interface_name, const char *signal_name,
    GVariant *parameters, gpointer user_data) {
  MonitoredSession *session_data = (MonitoredSession *)user_data;
  // check the name of added interface and that owner has changed from empty to non-empty
  gchar *name = NULL, *old_owner = NULL, *new_owner = NULL;
  g_variant_get(parameters, "(&s&s&s)", &name, &old_owner, &new_owner);    // `&s`s avoid `g_free()`
  if (g_strcmp0(name, KP_DBUS_INTERFACE) == 0 && (!old_owner || *old_owner == '\0') && new_owner &&
      *new_owner != '\0') {
    g_autoptr(GDBusConnection) system_conn = dbus_connect(true, true);
    if (!system_conn) return;
    print_info(
        "KeePassXC started, unlocking registered database(s) for UID=%u\n", session_data->user_id);
    unlock_databases(system_conn, session_data, 5);
    // unsubscribe to this signal here on (so if user closes and start KeePassXC again, then it
    // won't be auto-unlocked by design, though it will still have if session goes from
    // lock->unlock or inactive->active)
    guint kp_subscription_id = g_atomic_int_exchange(&session_data->kp_subscription_id, 0);
    if (kp_subscription_id != 0) {
      g_dbus_connection_signal_unsubscribe(session_conn, kp_subscription_id);
    }
  }
}


int main(int argc, char *argv[]) {
  if (geteuid() != 0) {
    print_error("This program must be run as root\n");
    return 1;
  }
  if (argc != 3) {
    show_usage(argv[0]);
    return 1;
  }

  // check if the first argument has a valid numeric user ID
  struct passwd *pwd = NULL;
  char *user_end = NULL;
  uid_t user_id = strtoul(argv[1], &user_end, 10);
  if (argv[1][0] != '\0' && *user_end == '\0') pwd = getpwuid(user_id);
  if (!pwd) {
    print_error("Invalid user ID %s\n", argv[1]);
    return 1;
  }
  user_id = pwd->pw_uid;
  const char *session_path = argv[2];

  // check if there are any database configuration files for the user
  if (!user_has_db_configs(user_id)) {
    print_error(
        "No configuration found for UID=%u - run 'sudo keepassxc-unlock-setup ...'\n", user_id);
    return 0;
  }

  print_info("Starting %s version %s\n", argv[0], PRODUCT_VERSION);

  // connect to the system bus
  g_autoptr(GDBusConnection) connection = dbus_connect(true, true);
  if (!connection) return 1;

  // get the session `Type` and `Display` properties
  g_autofree gchar *display = NULL;
  bool is_wayland = false;
  if (!session_valid_for_unlock(connection, session_path, user_id, NULL, &is_wayland, &display)) {
    print_error(
        "No valid X11/Wayland session found for UID=%u sessionPath='%s'\n", user_id, session_path);
    return 0;
  }

  // point DBUS_SESSION_BUS_ADDRESS to the user's session dbus
  char dbus_address[128];
  // TODO: obtain this from /proc/<pid>/environ of the lead process of the session
  snprintf(dbus_address, sizeof(dbus_address), "unix:path=/run/user/%u/bus", user_id);
  setenv("DBUS_SESSION_BUS_ADDRESS", dbus_address, 1);

  // start monitoring the session
  print_info("Monitoring session %s for UID=%u\n", session_path, user_id);
  g_autoptr(GMainLoop) loop = g_main_loop_new(NULL, FALSE);
  // subscribe to `PropertiesChanged` for the screen/session lock/unlock (`LockedHint`)
  // and session active/inactive events
  MonitoredSession user_data = {loop, session_path, user_id, is_wayland, display, false, true, 0};
  guint session_subscription_id = g_dbus_connection_signal_subscribe(connection,
      LOGIN_OBJECT_NAME,                      // sender
      DBUS_MAIN_OBJECT_NAME ".Properties",    // interface
      "PropertiesChanged",                    // signal name
      session_path,                           // object path
      NULL, G_DBUS_SIGNAL_FLAGS_NONE, handle_session_event, &user_data, NULL);
  if (session_subscription_id == 0) {
    print_error("Failed to subscribe to receive D-Bus signals for %s\n", session_path);
    return 1;
  }

  // subscribe to `SessionRemoved` signals separately which is on the main login object
  // while the session object itself does not receive any notification for its removal
  guint login_subscription_id = g_dbus_connection_signal_subscribe(connection, LOGIN_OBJECT_NAME,
      LOGIN_MANAGER_INTERFACE, "SessionRemoved", LOGIN_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
      handle_session_close, &user_data, NULL);
  if (login_subscription_id == 0) {
    print_error("Failed to subscribe to receive D-Bus signals for %s\n", LOGIN_OBJECT_PATH);
    g_dbus_connection_signal_unsubscribe(connection, session_subscription_id);
    return 1;
  }

  g_autoptr(GDBusConnection) session_conn = NULL;
  // unlock on startup since this program should be invoked on user session start
  print_info("Startup: unlocking registered KeePassXC database(s) for UID=%u\n", user_id);
  if (!unlock_databases(connection, &user_data, 15)) {
    // if unlock at startup failed, then subscribe to `NameOwnerChanged` signals to detect start
    // of KeePassXC (there is a small race here that KeePassXC start can happen between these
    // two which is fine since the worst case then is that auto-unlock didn't happen for a rare
    // case if KeePassXC wasn't started on session start)
    session_conn = dbus_session_connect(user_id, true);
    if (session_conn) {
      guint kp_subscription_id = g_dbus_connection_signal_subscribe(session_conn,
          DBUS_MAIN_OBJECT_NAME, DBUS_MAIN_OBJECT_NAME, "NameOwnerChanged", "/org/freedesktop/DBus",
          NULL, G_DBUS_SIGNAL_FLAGS_NONE, handle_keepassxc_start, &user_data, NULL);
      if (kp_subscription_id != 0) {
        g_atomic_int_set(&user_data.kp_subscription_id, kp_subscription_id);
        print_info("No KeePassXC running or failed to connect, monitoring KeePassXC start\n");
      }
    }
  }

  // run the main loop
  g_main_loop_run(loop);

  guint kp_subscription_id = g_atomic_int_exchange(&user_data.kp_subscription_id, 0);
  if (kp_subscription_id != 0 && session_conn) {
    g_dbus_connection_signal_unsubscribe(session_conn, kp_subscription_id);
  }
  g_dbus_connection_signal_unsubscribe(connection, login_subscription_id);
  g_dbus_connection_signal_unsubscribe(connection, session_subscription_id);

  return 0;
}
