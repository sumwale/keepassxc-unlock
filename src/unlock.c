#include "common.h"

#include <fcntl.h>
#include <glib.h>
#include <glob.h>
#include <pwd.h>
#include <sys/types.h>


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
  int kp_subscription_id;       // the subscription ID of KeePassXC `NameOwnerChanged` signals
} MonitoredSession;


/// @brief Show usage of this program.
/// @param script_name name of the invoking script as obtained from `argv[0]`
static void show_usage(const char *script_name) {
  g_print("\nUsage: %s [--version] <USER_ID> <SESSION_PATH>\n", script_name);
  g_print("\nMonitor a session for login and screen unlock events to unlock configured KeepassXC "
          "databases\n");
  g_print("\nArguments:\n");
  g_print("  --version       show the version string and exit\n\n");
  g_print("  <USER_ID>       numeric ID of user who owns the session to be monitored\n");
  g_print("  <SESSION_PATH>  the path of the session (ex. /org/freedesktop/login1/session/_3)\n\n");
}

/// @brief Check if given session is locked (i.e. `LockedHint` is true).
/// @param system_conn the `GBusConnection` object for the system D-Bus
/// @param session_path path of the selected session
/// @return boolean `LockedHint` property of the session
static bool is_locked(GDBusConnection *system_conn, const char *session_path) {
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) result = g_dbus_connection_call_sync(system_conn, LOGIN_OBJECT_NAME,
      session_path, DBUS_MAIN_OBJECT_NAME ".Properties", "Get",
      g_variant_new("(ss)", "org.freedesktop.login1.Session", "LockedHint"), NULL,
      G_DBUS_CALL_FLAGS_NONE, DBUS_CALL_WAIT, NULL, &error);
  if (!result) {
    g_warning("Failed to get LockedHint: %s", error ? error->message : "(null)");
    return true;
  }

  // extract boolean value wrapped inside the variant
  g_autoptr(GVariant) locked_variant = NULL;
  g_variant_get(result, "(v)", &locked_variant);
  return g_variant_get_boolean(locked_variant);
}

/// @brief Send a notification to the desktop using the D-Bus `org.freedesktop.Notifications` API
///        (like that done by `libnotify`/`notify-send`).
/// @param session_conn the `GBusConnection` object for the user's session D-Bus
/// @param name application name for the notification
/// @param icon icon filename or stock icon to display
/// @param summary summary of the notification message
/// @param body body of the notification message
/// @param urgency the urgency level of the notification (0 - low, 1 - normal, 2 - critical)
/// @param timeout duration, in milliseconds, for the notification to appear on screen
/// @return `true` if the notification was relayed successfully, `false` otherwise
static bool send_session_notification(GDBusConnection *session_conn, const gchar *name,
    const gchar *icon, const gchar *summary, const gchar *body, guint8 urgency, gint32 timeout) {
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
static bool verify_process_session(guint32 kp_pid, bool is_wayland, const gchar *display) {
  if (is_wayland) {
    // the `Display` property of the session is not set for the case of Wayland, and there is no way
    // to check if this is the same Wayland session (multiple Wayland sessions break stuff in many
    //   ways in any case) so just check that $WAYLAND_DISPLAY is not non-empty
    g_autofree const gchar *env_value = get_process_env_var(kp_pid, "WAYLAND_DISPLAY");
    return env_value && *env_value != '\0';
  } else {
    g_autofree const gchar *env_value = get_process_env_var(kp_pid, "DISPLAY");
    if (display && *display != '\0') {
      // when set, the value of $DISPLAY should match the passed `Display` session property
      return g_strcmp0(env_value, display) == 0;
    } else {
      // just check non-null value since `Display` session property may not be set
      // if the display manager that launched the session is running in Wayland mode
      return env_value && *env_value != '\0';
    }
  }
}

/// @brief Get the executable's SHA-512 hash from /proc/<pid>/exe and compare against the recorded
///        good checksum.
/// @param session_conn the `GBusConnection` object for the user's session D-Bus
/// @param user_conf_dir user's configuration directory (`/etc/keepassxc-unlock/<uid>`)
/// @param kp_pid process ID of KeePassXC
/// @return `true` if the checksum matched else `false`
static bool verify_process_exe_sha512(
    GDBusConnection *session_conn, const char *user_conf_dir, guint32 kp_pid) {
  // get the executable's SHA-512 hash from /proc/<pid>/exe and compare against the
  // recorded good checksum
  char kp_sha512_file[128], expected_sha512[256], kp_exe[128];
  snprintf(kp_sha512_file, sizeof(kp_sha512_file), "%s/keepassxc.sha512", user_conf_dir);
  FILE *file = fopen(kp_sha512_file, "r");
  if (!file) {
    g_warning(
        "Skipping unlock due to missing %s - run 'sudo keepassxc-unlock-setup'", kp_sha512_file);
    return false;
  }
  snprintf(kp_exe, sizeof(kp_exe), "/proc/%u/exe", kp_pid);
  g_autofree const gchar *current_sha512 = sha512sum(kp_exe);
  // use `fgets()` to read the sha512 file which is expected to have only one line
  // and replace terminating newline using `strcspn` (which works even if there was no newline)
  bool mismatch = !current_sha512 || !fgets(expected_sha512, sizeof(expected_sha512), file) ||
                  (expected_sha512[strcspn(expected_sha512, "\n")] = '\0',
                      strcmp(current_sha512, expected_sha512) != 0);
  fclose(file);
  if (mismatch) {
    // `kp_exe_full` stores the actual executable that /proc/<pid>/exe points to, while
    // `kp_exe_real` will either point to it or /proc/<pid>/exe in case read link was unsuccessful
    g_autofree const gchar *kp_exe_full = g_file_read_link(kp_exe, NULL);
    const gchar *kp_exe_real = kp_exe_full ? kp_exe_full : kp_exe;
    g_critical("Aborting unlock due to checksum mismatch in keepassxc (PID %u EXE %s)", kp_pid,
        kp_exe_real);
    g_autofree const gchar *notify_body = g_strdup_printf(
        "If KeePassXC has been updated, then run \"sudo keepassxc-unlock-setup ...\" for one of "
        "the KDBX databases.\nOtherwise this could be an unknown process snooping on D-Bus.\n\n "
        "The offending process ID is %u having executable pointing to %s",
        kp_pid, kp_exe_real);
    if (!send_session_notification(session_conn, "keepassxc-unlock", "system-lock-screen",
            "Checksum mismatch in keepassxc", notify_body, 2, 120000)) {
      g_critical("Failed to send D-Bus notification to the user for SHA-512 mismatch");
    }
    return false;
  }
  return true;
}

/// @brief Callback invoked when the `openDatabase` call finishes that logs if there was an error.
static void on_database_unlock(GDBusConnection *session_conn, GAsyncResult *res, gpointer data) {
  g_autofree gchar *kdbx_file = (gchar *)data;

  // From glib repository's gio/tests/gdbus-connection.c:
  //   Make sure gdbusconnection isn't holding @connection's lock. (#747349)
  g_dbus_connection_get_last_serial(session_conn);

  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) result = g_dbus_connection_call_finish(session_conn, res, &error);
  if (!result) {
    g_warning("Failed to unlock database '%s': %s", kdbx_file, error ? error->message : "(null)");
  }
}

/// @brief Unlock all the KDBX databases that were registered (using `keepassxc-unlock-setup`)
///        of the given user using KeePassXC's D-Bus API.
/// @param system_conn the `GBusConnection` object for the system D-Bus
/// @param session_data instance of `MonitoredSession` struct having information of the session
///                     being monitored
/// @param wait_secs seconds to try connecting to the KeePassXC D-Bus service before giving up
/// @param check_main_loop if set to `true` then check for `GMainLoop` to be running before unlock
/// @return `true` if connection was successful and unlock was attempted (though one or more
///         databases may have failed to unlock due to other reasons), and `false` if connection to
///         KeePassXC failed or session was still locked
static bool unlock_databases(GDBusConnection *system_conn, const MonitoredSession *session_data,
    int wait_secs, bool check_main_loop) {
  g_assert(session_data);

  g_autoptr(GDBusConnection) session_conn = NULL;
  // loop till `wait_secs` to get the ID of the process providing KeePassXC's D-Bus API
  guint32 kp_pid = 0;
  for (int i = 0; i < wait_secs; i++) {
    // log connection error only in the last iteration
    if (!session_conn) {
      session_conn = dbus_session_connect(session_data->user_id, i == wait_secs - 1);
    }
    if (session_conn &&
        (kp_pid = get_dbus_service_process_id(session_conn, KP_DBUS_INTERFACE)) != 0) {
      break;
    }
    sleep(1);
  }
  if (kp_pid == 0) {
    g_warning("Failed to connect to KeePassXC D-Bus API within %d secs", wait_secs);
    return false;
  }

  // verify from the KeePassXC executable's environment that it is running in the selected session
  if (!verify_process_session(kp_pid, session_data->is_wayland, session_data->display)) {
    g_warning("Skipping unlock due to mismatch of $DISPLAY/$WAYLAND_DISPLAY of KeePassXC process "
              "with ID %u against the session properties",
        kp_pid);
    return false;
  }

  // verify the KeePassXC executable's checksum
  char user_conf_dir[100];
  snprintf(user_conf_dir, sizeof(user_conf_dir), "%s/%u", KP_CONFIG_DIR, session_data->user_id);
  if (!verify_process_exe_sha512(session_conn, user_conf_dir, kp_pid)) return false;

  char conf_pattern[128], decrypted_passwd[MAX_PASSWORD_SIZE];
  snprintf(conf_pattern, sizeof(conf_pattern), "%s/" KP_CONFIG_PREFIX "*.conf", user_conf_dir);
  glob_t globbuf;
  if (glob(conf_pattern, 0, NULL, &globbuf) == 0) {
    // clear decrypted_passwd in every loop even if the loop condition fails
    for (size_t i = 0; memset(decrypted_passwd, 0, MAX_PASSWORD_SIZE), i < globbuf.gl_pathc; i++) {
      char *conf_path = globbuf.gl_pathv[i];
      g_autofree gchar *kdbx_file = NULL;
      g_autofree gchar *key_file = NULL;
      int passwd_start_line = read_configuration_file(conf_path, &kdbx_file, &key_file);
      if (passwd_start_line == -1) continue;

      // check for session end before unlocking
      if (check_main_loop && !g_main_loop_is_running(session_data->loop)) {
        g_warning("unlock_databases() aborting unlock due to session end");
        break;
      }

      char conf_name[128];
      const char *conf_filename = strrchr(conf_path, '/'), *conf_name_p;
      if (conf_filename && (conf_filename += sizeof(KP_CONFIG_PREFIX),    // sizeof() also adds +1
                               conf_name_p = strstr(conf_filename, ".conf")) != NULL) {
        size_t conf_name_len = MIN((size_t)(conf_name_p - conf_filename), sizeof(conf_name) - 1);
        memcpy(conf_name, conf_filename, conf_name_len);
        conf_name[conf_name_len] = '\0';
      }
      if (!decrypt_password(conf_path, conf_name, kdbx_file, passwd_start_line, decrypted_passwd,
              MAX_PASSWORD_SIZE)) {
        continue;
      }

      // last minute check to skip unlock if LockedHint is true
      if (is_locked(system_conn, session_data->session_path)) {
        g_warning("Skipping unlock since screen/session is still locked!");
        break;
      }

      g_dbus_connection_call(session_conn, KP_DBUS_INTERFACE, "/keepassxc", KP_DBUS_INTERFACE,
          "openDatabase", g_variant_new("(sss)", kdbx_file, decrypted_passwd, key_file), NULL,
          G_DBUS_CALL_FLAGS_NONE, -1, NULL, (GAsyncReadyCallback)on_database_unlock,
          g_strdup(kdbx_file) /* callback should have its own copy */);
    }
  }
  memset(decrypted_passwd, 0, MAX_PASSWORD_SIZE);
  globfree(&globbuf);
  return true;
}

/// @brief Callback to handle session signals on `org.freedesktop.login1` for selected session.
/// @param system_conn the `GBusConnection` object for the system D-Bus
/// @param sender_name name of the sender of the signal
/// @param object_path path of the object for which the signal was raised
/// @param interface_name D-Bus interface of the raised signal
/// @param signal_name name of the D-Bus signal that was raised
/// @param parameters parameters of the raised signal
/// @param user_data custom user data sent through with the signal which should be pointer to
///                  `MonitoredSession`
static void handle_session_event(GDBusConnection *system_conn, const char *sender_name,
    const char *object_path, const char *interface_name, const char *signal_name,
    GVariant *parameters, gpointer user_data) {
  MonitoredSession *session_data = (MonitoredSession *)user_data;
  g_autoptr(GVariantIter) iter = NULL;
  const gchar *key = NULL;
  GVariant *value = NULL;
  g_variant_get(parameters, "(sa{sv}as)", NULL, &iter, NULL);
  while (g_variant_iter_loop(iter, "{&sv}", &key, &value)) {
    if (g_strcmp0(key, "LockedHint") == 0) {
      bool locked = g_variant_get_boolean(value);
      if (!locked && session_data->session_locked) {
        g_message("Unlocking database(s) after screen/session unlock event");
        unlock_databases(system_conn, session_data, 5, true);
      }
      session_data->session_locked = locked;
    } else if (g_strcmp0(key, "Active") == 0) {
      bool active = g_variant_get_boolean(value);
      if (active && !session_data->session_active && !session_data->session_locked) {
        g_message("Unlocking database(s) after session activation event");
        unlock_databases(system_conn, session_data, 5, true);
      }
      session_data->session_active = active;
    }
  }
}

/// @brief Callback to handle session close for the selected session.
static void handle_session_close(GDBusConnection *system_conn, const char *sender_name,
    const char *object_path, const char *interface_name, const char *signal_name,
    GVariant *parameters, gpointer user_data) {
  MonitoredSession *session_data = (MonitoredSession *)user_data;
  gchar *removed_session_path = NULL;
  g_variant_get(parameters, "(s&o)", NULL, &removed_session_path);    // `&o` avoids `g_free()`
  if (g_strcmp0(removed_session_path, session_data->session_path) == 0) {
    g_message("Exit on session end for '%s'", session_data->session_path);
    g_main_loop_quit(session_data->loop);
  }
}

/// @brief Callback to handle KeePassXC startup when not present at the start of this process.
static void handle_keepassxc_start(GDBusConnection *session_conn, const char *sender_name,
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
    g_message(
        "KeePassXC started, unlocking registered database(s) for UID=%u", session_data->user_id);
    unlock_databases(system_conn, session_data, 5, true);
    // unsubscribe to this signal here on (so if user closes and start KeePassXC again, then it
    // won't be auto-unlocked by design, though it will still have if session goes from
    // lock->unlock or inactive->active)
    int kp_subscription_id = g_atomic_int_exchange(&session_data->kp_subscription_id, 0);
    if (kp_subscription_id != 0) {
      g_dbus_connection_signal_unsubscribe(session_conn, (guint)kp_subscription_id);
    }
  }
}


int main_unlock(int argc, char *argv[]) {
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    g_print("%s\n", PRODUCT_VERSION);
    return 0;
  }
  if (geteuid() != 0) {
    g_printerr("This program must be run as root\n");
    return 1;
  }
  if (argc != 3) {
    show_usage(argv[0]);
    return 1;
  }

  // check if the first argument has a valid numeric user ID
  struct passwd *pwd = NULL;
  char *user_end = NULL;
  uid_t user_id = (uid_t)strtoul(argv[1], &user_end, 10);
  if (argv[1][0] != '\0' && *user_end == '\0') pwd = getpwuid(user_id);
  if (!pwd) {
    g_printerr("Invalid user ID %s\n", argv[1]);
    return 1;
  }
  user_id = pwd->pw_uid;
  const char *session_path = argv[2];

  // check if there are any database configuration files for the user
  if (!user_has_db_configs(user_id)) {
    g_printerr(
        "No configuration found for UID=%u - run 'sudo keepassxc-unlock-setup ...'\n", user_id);
    return 0;
  }

  g_message("Starting %s version %s", argv[0], PRODUCT_VERSION);

  // connect to the system bus
  g_autoptr(GDBusConnection) system_conn = dbus_connect(true, true);
  if (!system_conn) return 1;

  // get the session `Type`, `Display` and `Scope` properties
  g_autofree gchar *display = NULL;
  g_autofree gchar *scope = NULL;
  bool is_wayland = false;
  if (!session_valid_for_unlock(
          system_conn, session_path, user_id, NULL, &is_wayland, &display, &scope)) {
    g_warning(
        "No valid X11/Wayland session found for UID=%u in sessionPath='%s'", user_id, session_path);
    return 0;
  }

  // point `DBUS_SESSION_BUS_ADDRESS` to the user's session dbus
  g_autofree const gchar *session_dbus_address = NULL;
  for (int i = 0; i < MAX_TRIES; i++) {
    if ((session_dbus_address = get_session_bus_address(system_conn, scope)) != NULL) break;
    sleep(1);
  }
  // fallback to default if `DBUS_SESSION_BUS_ADDRESS` is not set for any process of this session
  // (note that keepassxc will likely not "belong" to this session, since in systemd-logind setups
  //    user's session systemd daemon is root for most processes which detaches from session)
  if (!session_dbus_address) {
    g_warning("Failed to find DBUS_SESSION_BUS_ADDRESS in the environment of any of the processes "
              "belonging to the scope '%s' of this session. Falling back to the default value.",
        scope);
    session_dbus_address = g_strdup_printf("unix:path=/run/user/%u/bus", user_id);
  }
  setenv("DBUS_SESSION_BUS_ADDRESS", session_dbus_address, 1);

  // start monitoring the session
  g_message("Monitoring session %s for UID=%u", session_path, user_id);
  g_autoptr(GMainLoop) loop = g_main_loop_new(NULL, FALSE);
  // subscribe to `PropertiesChanged` for the screen/session lock/unlock (`LockedHint`)
  // and session active/inactive events
  MonitoredSession user_data = {loop, session_path, user_id, is_wayland, display, false, true, 0};
  guint session_subscription_id = g_dbus_connection_signal_subscribe(system_conn,
      LOGIN_OBJECT_NAME,                      // sender
      DBUS_MAIN_OBJECT_NAME ".Properties",    // interface
      "PropertiesChanged",                    // signal name
      session_path,                           // object path
      NULL, G_DBUS_SIGNAL_FLAGS_NONE, handle_session_event, &user_data, NULL);
  if (session_subscription_id == 0) {
    g_warning("Failed to subscribe to receive D-Bus signals for %s", session_path);
    return 1;
  }

  // subscribe to `SessionRemoved` signals separately which is on the main login object
  // while the session object itself does not receive any notification for its removal
  guint login_subscription_id = g_dbus_connection_signal_subscribe(system_conn, LOGIN_OBJECT_NAME,
      LOGIN_MANAGER_INTERFACE, "SessionRemoved", LOGIN_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
      handle_session_close, &user_data, NULL);
  if (login_subscription_id == 0) {
    g_warning("Failed to subscribe to receive D-Bus signals for %s", LOGIN_OBJECT_PATH);
    g_dbus_connection_signal_unsubscribe(system_conn, session_subscription_id);
    return 1;
  }

  g_autoptr(GDBusConnection) session_conn = NULL;
  // unlock on startup since this program should be invoked on user session start
  g_message("Startup: unlocking registered KeePassXC database(s) for UID=%u", user_id);
  if (!unlock_databases(system_conn, &user_data, 15, false)) {
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
        g_atomic_int_set(&user_data.kp_subscription_id, (int)kp_subscription_id);
        g_message("No KeePassXC running or failed to connect, monitoring KeePassXC start");
      }
    }
  }

  // run the main loop
  g_main_loop_run(loop);

  // unsubscribe
  int kp_subscription_id = g_atomic_int_exchange(&user_data.kp_subscription_id, 0);
  if (kp_subscription_id != 0 && session_conn) {
    g_dbus_connection_signal_unsubscribe(session_conn, (guint)kp_subscription_id);
  }
  g_dbus_connection_signal_unsubscribe(system_conn, login_subscription_id);
  g_dbus_connection_signal_unsubscribe(system_conn, session_subscription_id);

  return 0;
}
