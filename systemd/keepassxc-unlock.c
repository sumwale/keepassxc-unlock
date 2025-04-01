#include <fcntl.h>
#include <gio/gio.h>
#include <glib.h>
#include <glob.h>
#include <openssl/evp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define KP_CONFIG_DIR "/etc/keepassxc-unlock"
#define SHA512_BUFFER_SIZE EVP_MAX_MD_SIZE * 2 + 1

#define DBUS_CALL_WAIT 60000    // in milliseconds
#define LOGIN_OBJECT_NAME "org.freedesktop.login1"
#define LOGIN_OBJECT_PATH "/org/freedesktop/login1"
#define LOGIN_MANAGER_INTERFACE "org.freedesktop.login1.Manager"
#define KP_DBUS_INTERFACE "org.keepassxc.KeePassXC.MainWindow"

/// @brief Show usage of this program
/// @param script_name name of the invoking script as obtained from `argv[0]`
void show_usage(const char *script_name) {
  printf("\nUsage: %s <USER>\n", script_name);
  printf("\nMonitor a session for login and screen unlock events to unlock configured KeepassXC "
         "databases\n");
  printf("\nArguments:\n");
  printf("  <USER>          user name or ID to be monitored\n\n");
}

/// @brief Select the current X11/Wayland login session of the user.
///        If there are multiple for the user, then the first one in the list is returned.
/// @param connection the `GBusConnection` object for the system D-Bus
/// @param user_id the numeric ID of the user
/// @return the `path` of the selected session (e.g. `/org/freedesktop/login1/session/_3337`)
gchar *select_session(GDBusConnection *connection, uid_t user_id) {
  // This uses ListSessions and then iterates through the returned list.
  // Another option can be to use introspection on the root of sessions then traverse the XML
  // output which will take a single call, but that was not chosen since XML traversal is
  // unnecessarily complex.
  GError *error = NULL;
  GVariant *sessions = g_dbus_connection_call_sync(connection, LOGIN_OBJECT_NAME, LOGIN_OBJECT_PATH,
      LOGIN_MANAGER_INTERFACE, "ListSessions", NULL, NULL, G_DBUS_CALL_FLAGS_NONE, DBUS_CALL_WAIT,
      NULL, &error);
  if (!sessions) {
    fprintf(stderr, "Failed to list sessions: %s\n", error ? error->message : "(null)");
    if (error) g_error_free(error);
    return NULL;
  }

  gchar *session_path = NULL;
  guint32 uid = -1;
  GVariantIter *iter = NULL;
  // pick the first session that matches: user_id, Type=x11|wayland, Remote=false, Active=true
  g_variant_get(sessions, "(a(susso))", &iter);
  while (g_variant_iter_loop(iter, "(susso)", NULL, &uid, NULL, NULL, &session_path)) {
    if (user_id != uid) continue;    // skip other users

    GVariant *session_props = g_dbus_connection_call_sync(connection, LOGIN_OBJECT_NAME,
        session_path, "org.freedesktop.DBus.Properties", "GetAll",
        g_variant_new("(s)", "org.freedesktop.login1.Session"), NULL, G_DBUS_CALL_FLAGS_NONE,
        DBUS_CALL_WAIT, NULL, &error);
    if (!session_props) {
      fprintf(stderr, "Failed to get properties for %s: %s\n", session_path,
          error ? error->message : "(null)");
      if (error) g_error_free(error);
      continue;
    }

    GVariantIter *iter_inner = NULL;
    g_variant_get(session_props, "(a{sv})", &iter_inner);
    bool s_supported_type = false, s_remote = false, s_active = false;
    const char *key = NULL;
    GVariant *value = NULL;
    while (g_variant_iter_loop(iter_inner, "{&sv}", &key, &value)) {
      if (g_strcmp0(key, "Type") == 0) {
        const char *type_val = g_variant_get_string(value, NULL);
        s_supported_type = g_strcmp0(type_val, "x11") == 0 || g_strcmp0(type_val, "wayland") == 0;
      } else if (g_strcmp0(key, "Remote") == 0) {
        s_remote = g_variant_get_boolean(value);
      } else if (g_strcmp0(key, "Active") == 0) {
        s_active = g_variant_get_boolean(value);
      }
    }
    g_variant_iter_free(iter_inner);
    g_variant_unref(session_props);
    if (s_supported_type && !s_remote && s_active) {
      // returning this session_path hence don't g_free() unlike other cases when
      // breaking out of g_variant_iter_loop()
      break;
    }
  }
  g_variant_iter_free(iter);
  g_variant_unref(sessions);
  return session_path;
}

/// @brief Check if given session is locked (i.e. `LockedHint` is true)
/// @param connection the `GBusConnection` object for the system D-Bus
/// @param session_path path of the selected session
/// @return boolean `LockedHint` property of the session
bool is_locked(GDBusConnection *connection, const char *session_path) {
  GError *error = NULL;
  GVariant *result = g_dbus_connection_call_sync(connection, LOGIN_OBJECT_NAME, session_path,
      "org.freedesktop.DBus.Properties", "Get",
      g_variant_new("(ss)", "org.freedesktop.login1.Session", "LockedHint"), NULL,
      G_DBUS_CALL_FLAGS_NONE, DBUS_CALL_WAIT, NULL, &error);
  if (!result) {
    fprintf(stderr, "Failed to get LockedHint: %s\n", error ? error->message : "(null)");
    if (error) g_error_free(error);
    return true;
  }

  GVariant *locked_variant = NULL;
  g_variant_get(result, "(v)", &locked_variant);
  bool locked = g_variant_get_boolean(locked_variant);
  g_variant_unref(locked_variant);
  g_variant_unref(result);

  return locked;
}

/// @brief Change the effective user ID to the given one with error checking.
///        Exit the whole program with code 1 if it fails to change effective UID back to 0.
/// @param uid the user ID to be set as the effective UID
void change_euid(uid_t uid) {
  if (geteuid() == uid) return;
  if (seteuid(uid) != 0) {
    fprintf(stderr, "Failed to seteuid to %d: ", uid);
    fflush(stderr);
    perror(NULL);
    if (uid == 0) {    // failed to switch back to root?
      fprintf(stderr, "\033[1;31mCannot switch back to root, terminating...\033[00m");
      exit(1);
    }
  }
}

/// @brief Get the process ID registered for given D-Bus API on the session bus.
///        Since this uses the session bus, the call should be done after changing
///        the effective UID of this process to the target user.
/// @param dbus_api the D-Bus API that the process has registered
/// @return the process ID registered for the D-Bus API or 0 if something went wrong
guint32 get_dbus_service_process_id(const char *dbus_api) {
  GError *error = NULL;
  GDBusConnection *session_conn = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
  if (!session_conn) {
    fprintf(stderr, "Failed to connect to session bus: %s\n", error ? error->message : "(null)");
    if (error) g_error_free(error);
    return 0;
  }
  GVariant *result = g_dbus_connection_call_sync(session_conn, "org.freedesktop.DBus", "/",
      "org.freedesktop.DBus", "GetConnectionUnixProcessID", g_variant_new("(s)", dbus_api), NULL,
      G_DBUS_CALL_FLAGS_NONE, DBUS_CALL_WAIT, NULL, &error);
  g_object_unref(session_conn);
  if (result) {
    guint32 pid = 0;
    g_variant_get(result, "(u)", &pid);
    return pid;
  } else {
    if (error) g_error_free(error);
    return 0;
  }
}

/// @brief Calculate the SHA-512 hash for the given file and return as a hexadecimal
///        string in the given buffer.
/// @param path path of the file for which SHA-512 hash has to be calculated
/// @param hash_buffer fill the SHA-512 hash as a hexadecimal string with terminating null
/// @param buffer_size total size of the passed `hash_buffer`
/// @return length of the `hash_buffer` excluding terminating null, or 0 in case of failure
size_t sha512sum(const char *path, char *hash_buffer, size_t buffer_size) {
  int fd = open(path, O_RDONLY);
  if (fd == -1) {
    perror("sha512sum() failed to open file");
    return 0;
  }

  unsigned char buffer[32768];
  ssize_t bytes_read;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;
  // keep on heap to maintain compatibility in case of EVP_MD_CTX struct size change
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(md_ctx, EVP_sha512(), NULL);
  while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
    EVP_DigestUpdate(md_ctx, buffer, bytes_read);
  }
  close(fd);
  EVP_DigestFinal_ex(md_ctx, hash, &hash_len);
  EVP_MD_CTX_free(md_ctx);
  if (bytes_read == -1) {
    perror("sha512sum() failed to read file");
    return 0;
  }

  size_t buf_len = 0;
  for (size_t i = 0; i < hash_len && buf_len < buffer_size - 1; i++, buf_len += 2) {
    sprintf(hash_buffer + buf_len, "%02x", hash[i]);
  }
  hash_buffer[buf_len] = '\0';
  return buf_len;
}

/// @brief Unlock all the registered KDBX databases (using `keepassxc-unlock-setup`) of the
///        given user using KeePassXC's D-Bus API.
/// @param user_id the numeric ID of the user
/// @param system_conn the `GBusConnection` object for the system D-Bus
/// @param session_path path of the selected session
/// @param wait_secs seconds to try connecting to the KeePassXC D-Bus service before giving up
void unlock_databases(
    uid_t user_id, GDBusConnection *system_conn, const char *session_path, int wait_secs) {
  // last minute check to skip unlock if LockedHint is true
  if (is_locked(system_conn, session_path)) {
    fprintf(stderr, "Skipping unlock since screen/session is still locked!\n");
    return;
  }

  // point DBUS_SESSION_BUS_ADDRESS to the user's session dbus
  char dbus_address[128], user_conf_dir[100];
  snprintf(dbus_address, sizeof(dbus_address), "unix:path=/run/user/%d/bus", user_id);
  snprintf(user_conf_dir, sizeof(user_conf_dir), "%s/%d", KP_CONFIG_DIR, user_id);
  setenv("DBUS_SESSION_BUS_ADDRESS", dbus_address, 1);

  bool kp_exe_verified = false;
  for (int i = 0; i < wait_secs; i++) {
    // check the process accepting the KeePassXC D-Bus messages and verify its checksum
    change_euid(user_id);
    guint32 kp_pid = get_dbus_service_process_id(KP_DBUS_INTERFACE);
    change_euid(0);
    if (kp_pid == 0) {
      sleep(1);
      continue;
    }
    char expected_sha512[SHA512_BUFFER_SIZE], current_sha512[SHA512_BUFFER_SIZE];
    char kp_sha512_file[128], kp_exe[128];
    snprintf(kp_sha512_file, sizeof(kp_sha512_file), "%s/keepassxc.sha512", user_conf_dir);
    FILE *file = fopen(kp_sha512_file, "r");
    if (!file) {
      fprintf(stderr, "Skipping unlock due to missing %s -- run 'sudo keepassxc-unlock-setup'\n",
          kp_sha512_file);
      return;
    }
    snprintf(kp_exe, sizeof(kp_exe), "/proc/%d/exe", kp_pid);
    bool mismatch = sha512sum(kp_exe, current_sha512, SHA512_BUFFER_SIZE) == 0;
    mismatch = mismatch || !fgets(expected_sha512, sizeof(expected_sha512), file) ||
               (expected_sha512[strcspn(expected_sha512, "\n")] = '\0',
                   g_strcmp0(current_sha512, expected_sha512) != 0);
    fclose(file);
    if (mismatch) {
      char kp_exe_full[PATH_MAX], *kp_exe_real = kp_exe;
      ssize_t kp_full_len = readlink(kp_exe, kp_exe_full, sizeof(kp_exe_full) - 1);
      if (kp_full_len > 0) {
        kp_exe_full[kp_full_len] = '\0';
        kp_exe_real = kp_exe_full;
      }
      fprintf(stderr,
          "\033[1;33mAborting unlock due to checksum mismatch in keepassxc (PID %d EXE %s)"
          "\033[00m\n",
          kp_pid, kp_exe_real);
      char notify_cmd[PATH_MAX * 2];
      snprintf(notify_cmd, sizeof(notify_cmd),
          "runuser -u `id -un %d` -- notify-send -i system-lock-screen -u critical -t 0 "
          "'Checksum mismatch in keepassxc' 'If KeePassXC has been updated, then run "
          "\"sudo keepassxc-unlock-setup ...\" for one of the KDBX databases.\nOtherwise this "
          "could be an unknown process snooping on D-Bus.\nThe offending process ID is %d "
          "having executable pointing to %s'",
          user_id, kp_pid, kp_exe_real);
      if (system(notify_cmd) != 0) {
        perror("unlock_databases() failed to notify-send for SHA-512 mismatch");
      }
      return;
    } else {
      kp_exe_verified = true;
    }
    break;
  }
  if (!kp_exe_verified) {
    fprintf(stderr, "Failed to verify KeePassXC executable within %d secs\n", wait_secs);
    return;
  }

  char conf_pattern[128];
  snprintf(conf_pattern, sizeof(conf_pattern), "%s/*.conf", user_conf_dir);
  glob_t globbuf;
  if (glob(conf_pattern, 0, NULL, &globbuf) == 0) {
    for (size_t i = 0; i < globbuf.gl_pathc; i++) {
      char *conf_path = globbuf.gl_pathv[i];
      FILE *file = fopen(conf_path, "r");
      if (!file) {
        fprintf(stderr, "Failed to open configuration file: %s\n", conf_path);
        continue;
      }

      char line[1024];
      char kdbx_file[1024] = {0};
      char key_file[1024] = {0};
      char enc_pwd[4096] = {0};
      while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "DB=", 3) == 0) {
          strncpy(kdbx_file, line + 3, sizeof(kdbx_file) - 1);
          kdbx_file[strcspn(kdbx_file, "\n")] = '\0';
        } else if (strncmp(line, "KEY=", 4) == 0) {
          strncpy(key_file, line + 4, sizeof(key_file) - 1);
          key_file[strcspn(key_file, "\n")] = '\0';
        } else if (strncmp(line, "PASSWORD:", 9) == 0) {
          continue;
        } else {
          strncat(enc_pwd, line, sizeof(enc_pwd) - strlen(enc_pwd) - 1);
        }
      }
      fclose(file);

      char conf_name[128] = {0}, decrypt_cmd[8192], decrypted_pwd[4096];
      char *conf_name_p, *conf_filename = strrchr(conf_path, '/');
      if (conf_filename != NULL && (conf_name_p = strstr(conf_filename + 1, ".conf")) != NULL) {
        size_t conf_name_len = conf_name_p - conf_filename - 1;
        strncpy(conf_name, conf_filename + 1, MIN(conf_name_len, sizeof(conf_name)));
      }
      snprintf(decrypt_cmd, sizeof(decrypt_cmd),
          "echo -n '%s' | systemd-creds --name='%s' decrypt - -", enc_pwd, conf_name);
      FILE *pipe = popen(decrypt_cmd, "r");
      if (!pipe) {
        perror("Failed to run systemd-creds for decryption");
        continue;
      }
      size_t len = fread(decrypted_pwd, 1, sizeof(decrypted_pwd), pipe);
      decrypted_pwd[len] = '\0';
      pclose(pipe);

      change_euid(user_id);
      GError *error = NULL;
      GDBusConnection *session_conn = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
      if (!session_conn) {
        fprintf(
            stderr, "Failed to connect to session bus: %s\n", error ? error->message : "(null)");
        if (error) g_error_free(error);
        change_euid(0);
        continue;
      }
      GVariant *result = g_dbus_connection_call_sync(session_conn, KP_DBUS_INTERFACE, "/keepassxc",
          KP_DBUS_INTERFACE, "openDatabase",
          g_variant_new("(sss)", kdbx_file, decrypted_pwd, key_file), NULL, G_DBUS_CALL_FLAGS_NONE,
          DBUS_CALL_WAIT, NULL, &error);
      memset(decrypted_pwd, 0, sizeof(decrypted_pwd));
      if (result) {
        g_variant_unref(result);
      } else {
        fprintf(stderr, "Failed to unlock database '%s': %s\n", kdbx_file,
            error ? error->message : "(null)");
        if (error) g_error_free(error);
      }
      g_object_unref(session_conn);
      change_euid(0);
    }
  }
  globfree(&globbuf);
}

/// @brief Holds the fields for `user_data` passed to the `handle_session_event` callback
typedef struct {
  GMainLoop *loop;              // the main loop object pointer
  const gchar *session_path;    // path of the selected session
  uid_t user_id;                // numeric ID of the user
  bool session_locked;          // holds the previous locked state of the session
  bool session_active;          // holds the previous active state of the session
} session_loop_data;

/// @brief Callback to handle session events on `org.freedesktop.login1`
/// @param conn the `GBusConnection` object for the system D-Bus
/// @param sender_name name of the sender of the event
/// @param object_path path of the object for which the event was raised
/// @param interface_name D-Bus interface of the raised signal
/// @param signal_name name of the D-Bus signal that was raised
/// @param parameters parameters of the raised signal
/// @param user_data custom user data sent through with the event
void handle_session_event(GDBusConnection *conn, const char *sender_name, const char *object_path,
    const char *interface_name, const char *signal_name, GVariant *parameters, gpointer user_data) {
  session_loop_data *session_data = (session_loop_data *)user_data;

  if (g_strcmp0(object_path, LOGIN_OBJECT_PATH) == 0) {
    // check for session close
    if (g_strcmp0(interface_name, LOGIN_MANAGER_INTERFACE) == 0 &&
        g_strcmp0(signal_name, "SessionRemoved") == 0) {
      char *removed_session_path = "";
      g_variant_get(parameters, "(so)", NULL, &removed_session_path);
      bool session_removed = g_strcmp0(removed_session_path, session_data->session_path) == 0;
      g_free(removed_session_path);
      if (session_removed) {
        printf("Exit on session end for %s\n", session_data->session_path);
        g_main_loop_quit(session_data->loop);
      }
    }
    return;
  } else if (g_strcmp0(object_path, session_data->session_path) != 0) {
    return;
  }

  GVariantIter *iter = NULL;
  const char *key;
  GVariant *value = NULL;
  g_variant_get(parameters, "(sa{sv}as)", NULL, &iter, NULL);
  while (g_variant_iter_loop(iter, "{&sv}", &key, &value)) {
    if (g_strcmp0(key, "LockedHint") == 0) {
      bool locked = g_variant_get_boolean(value);
      if (!locked && session_data->session_locked) {
        printf("Unlocking database(s) after screen/session unlock event\n");
        unlock_databases(session_data->user_id, conn, session_data->session_path, 10);
      }
      session_data->session_locked = locked;
    } else if (g_strcmp0(key, "Active") == 0) {
      bool active = g_variant_get_boolean(value);
      if (active && !session_data->session_active && !session_data->session_locked) {
        printf("Unlocking database(s) after session activation event\n");
        unlock_databases(session_data->user_id, conn, session_data->session_path, 30);
      }
      session_data->session_active = active;
    }
  }
  g_variant_iter_free(iter);
}


int main(int argc, char *argv[]) {
  if (argc != 2) {
    show_usage(argv[0]);
    return 1;
  }
  if (geteuid() != 0) {
    fprintf(stderr, "This utility must be run as root\n");
    return 1;
  }
  // check if the given string is numeric ID or name
  struct passwd *pwd;
  char *arg_end;
  uid_t user_id = strtoul(argv[1], &arg_end, 10);
  if (argv[1][0] != '\0' && *arg_end == '\0') {
    pwd = getpwuid(user_id);
  } else {
    pwd = getpwnam(argv[1]);
  }
  if (!pwd) {
    fprintf(stderr, "Invalid user or ID '%s'\n", argv[1]);
    return 1;
  }
  user_id = pwd->pw_uid;

  char user_conf_dir[100], conf_pattern[128];
  glob_t globbuf;
  snprintf(user_conf_dir, sizeof(user_conf_dir), "%s/%d", KP_CONFIG_DIR, user_id);
  snprintf(conf_pattern, sizeof(conf_pattern), "%s/*.conf", user_conf_dir);
  bool glob_nomatch = glob(conf_pattern, 0, NULL, &globbuf) != 0 || globbuf.gl_pathc == 0;
  globfree(&globbuf);
  if (glob_nomatch) {
    fprintf(stderr, "No configuration found for %d -- run keepassxc-unlock-setup first\n", user_id);
    return 0;
  }

  GError *error = NULL;
  GDBusConnection *connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
  if (!connection) {
    fprintf(stderr, "Failed to connect to system bus: %s\n", error ? error->message : "(null)");
    if (error) g_error_free(error);
    return 1;
  }
  gchar *session_path = NULL;
  for (int i = 0; i < 30; i++) {
    session_path = select_session(connection, user_id);
    if (session_path) break;
    sleep(1);
  }
  if (!session_path) {
    fprintf(stderr, "No valid X11/Wayland session found for UID=%d\n", user_id);
    return 0;
  }

  // unlock on session startup
  printf("Startup: unlocking registered KeePassXC database(s) for UID=%d\n", user_id);
  unlock_databases(user_id, connection, session_path, 60);

  printf("Monitoring session %s for UID=%d\n", session_path, user_id);
  GMainLoop *loop = g_main_loop_new(NULL, FALSE);
  session_loop_data user_data = {loop, session_path, user_id, false, true};
  g_dbus_connection_signal_subscribe(connection, LOGIN_OBJECT_NAME, NULL, NULL, NULL, NULL,
      G_DBUS_SIGNAL_FLAGS_NONE, handle_session_event, &user_data, NULL);
  g_main_loop_run(loop);

  g_object_unref(connection);
  g_main_loop_unref(loop);
  g_free(session_path);
  return 0;
}
