#include "common.h"

#include <fcntl.h>
#include <glob.h>
#include <sys/types.h>


GDBusConnection *dbus_connect(bool system_bus, bool log_error) {
  g_autoptr(GError) error = NULL;
  GDBusConnection *connection =
      g_bus_get_sync(system_bus ? G_BUS_TYPE_SYSTEM : G_BUS_TYPE_SESSION, NULL, &error);
  if (!connection) {
    if (log_error) {
      g_warning("Failed to connect to %s bus: %s", system_bus ? "system" : "session",
          error ? error->message : "(null)");
    }
  }
  return connection;
}

void change_euid(uid_t uid) {
  if (geteuid() == uid) return;
  if (seteuid(uid) != 0) {
    g_critical("change_euid() failed in seteuid to %u: %s", uid, STR_ERROR);
    if (uid == 0) {    // failed to switch back to root?
      g_error("Cannot switch back to root, terminating...");
      exit(1);
    }
  }
}

GDBusConnection *dbus_session_connect(uid_t user_id, bool log_error) {
  // switch effective ID to the user before connecting since this is the user's session bus
  change_euid(user_id);
  GDBusConnection *session_conn = dbus_connect(false, log_error);
  change_euid(0);
  return session_conn;
}

bool user_has_db_configs(guint32 user_id) {
  char conf_pattern[128];
  glob_t globbuf;

  // construct the configuration directory and pattern
  snprintf(conf_pattern, sizeof(conf_pattern), "%s/%u/" KP_CONFIG_PREFIX "*.conf", KP_CONFIG_DIR,
      user_id);

  // check if there are any configuration files in the user-specific configuration directory
  bool has_configs = glob(conf_pattern, 0, NULL, &globbuf) == 0 && globbuf.gl_pathc > 0;
  globfree(&globbuf);
  return has_configs;
}

int session_valid_for_unlock(GDBusConnection *system_conn, const gchar *session_path,
    guint32 check_uid, guint32 *out_uid_ptr, bool *is_wayland_ptr, gchar **display_ptr,
    gchar **scope_ptr) {
  g_autoptr(GError) error = NULL;
  // get all properties of the session
  g_autoptr(GVariant) session_props = g_dbus_connection_call_sync(system_conn, LOGIN_OBJECT_NAME,
      session_path, DBUS_MAIN_OBJECT_NAME ".Properties", "GetAll",
      g_variant_new("(s)", "org.freedesktop.login1.Session"), NULL, G_DBUS_CALL_FLAGS_NONE,
      DBUS_CALL_WAIT, NULL, &error);
  if (!session_props) {
    g_warning(
        "Failed to get properties for '%s': %s", session_path, error ? error->message : "(null)");
    return 0;
  }

  // parse the properties to check if the session is valid
  g_autoptr(GVariantIter) iter = NULL;
  g_variant_get(session_props, "(a{sv})", &iter);

  bool user_match = false, has_supported_type = false, is_remote = false, is_active = false;
  const gchar *key = NULL;
  GVariant *value = NULL;
  while (g_variant_iter_loop(iter, "{&sv}", &key, &value)) {
    if (g_strcmp0(key, "User") == 0) {
      user_match = true;
      guint32 user_id = 0;
      g_variant_get(value, "(uo)", &user_id, NULL);
      if (out_uid_ptr) {
        *out_uid_ptr = user_id;
      } else if (check_uid != user_id) {
        g_warning("Session not valid due to mismatch in given user ID %u from actual owner %u",
            check_uid, user_id);
        user_match = false;
      }
    } else if (g_strcmp0(key, "Display") == 0) {
      if (display_ptr) g_variant_get(value, "s", display_ptr);
    } else if (g_strcmp0(key, "Remote") == 0) {
      is_remote = g_variant_get_boolean(value);
    } else if (g_strcmp0(key, "Scope") == 0) {
      if (scope_ptr) g_variant_get(value, "s", scope_ptr);
    } else if (g_strcmp0(key, "Type") == 0) {
      const char *type_val = g_variant_get_string(value, NULL);
      bool is_wayland = g_strcmp0(type_val, "wayland") == 0;
      has_supported_type = is_wayland || g_strcmp0(type_val, "x11") == 0;
      if (has_supported_type && is_wayland_ptr) *is_wayland_ptr = is_wayland;
    } else if (g_strcmp0(key, "State") == 0) {
      const char *state = g_variant_get_string(value, NULL);
      is_active = g_strcmp0(state, "active") == 0 || g_strcmp0(state, "opening") == 0;
    }
  }

  // a session is a target for auto-unlock if it is of a supported type, not remote, and active
  if (user_match && !is_remote && is_active) return has_supported_type ? 1 : 2;
  return 0;
}

gchar *get_process_env_var(guint32 pid, const char *env_var) {
  gchar env_file[128];
  snprintf(env_file, sizeof(env_file), "/proc/%u/environ", pid);

  // since the size of initial process environment is limited to ARG_MAX, its safe to read the
  // entire file in one go
  g_autofree gchar *env = NULL;
  gsize env_len = 0;
  g_autoptr(GError) error = NULL;
  if (!g_file_get_contents(env_file, &env, &env_len, &error)) {
    g_warning("Failed to read file '%s': %s", env_file, error ? error->message : "(null)");
    return NULL;
  }
  // strings are null separated in /proc/<pid>/environ, so use strlen to skip over
  size_t var_len = strlen(env_var);
  gchar *env_ptr = env, *env_end = env + env_len, *var_value = NULL;
  while (env_ptr < env_end) {
    size_t current_len = strlen(env_ptr);
    if (current_len > var_len && strncmp(env_ptr, env_var, var_len) == 0 &&
        env_ptr[var_len] == '=') {
      var_value = g_strndup(env_ptr + var_len + 1, current_len - var_len - 1);
      break;
    }
    env_ptr += current_len + 1;
  }
  return var_value;
}

guint32 get_dbus_service_process_id(GDBusConnection *session_conn, const char *dbus_api) {
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

gchar *sha512sum(const char *path) {
  // create a new checksum context for SHA-512
  g_autoptr(GChecksum) checksum = g_checksum_new(G_CHECKSUM_SHA512);
  if (!checksum) {
    g_warning("sha512sum() failed to create checksum context");
    return NULL;
  }

  // open the file using low-level `open()` API for best performance
  int fd = open(path, O_RDONLY);
  if (fd == -1) {
    g_warning("sha512sum() failed to open file: %s", STR_ERROR);
    return NULL;
  }

  // read data from the file in chunks and keep updating the checksum
  guchar buffer[32768];
  ssize_t bytes_read;
  while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
    g_checksum_update(checksum, buffer, bytes_read);
  }
  if (bytes_read == -1) g_warning("sha512sum() failed to read file: %s", STR_ERROR);
  close(fd);
  if (bytes_read == -1) return NULL;

  // get the final checksum as a hexadecimal string
  const gchar *hex_hash = g_checksum_get_string(checksum);
  return g_strdup(hex_hash);
}

int read_configuration_file(const char *conf_file, gchar **kdbx_file, gchar **key_file) {
  FILE *file = fopen(conf_file, "r");
  if (!file) {
    g_warning("Failed to open configuration file: %s", conf_file);
    return -1;
  }

  char line[PATH_MAX + 4];
  int passwd_start_line = -1, current_line = 0;
  while (fgets(line, sizeof(line), file)) {
    current_line++;
    if (strncmp(line, "DB=", 3) == 0) {
      if (kdbx_file) {
        *kdbx_file = g_strdup(line + 3);
        (*kdbx_file)[strcspn(*kdbx_file, "\n")] = '\0';
      }
    } else if (strncmp(line, "KEY=", 4) == 0) {
      if (key_file) {
        *key_file = g_strdup(line + 4);
        (*key_file)[strcspn(*key_file, "\n")] = '\0';
      }
    } else if (strncmp(line, "PASSWORD:", 9) != 0) {
      // password starts after the line having PASSWORD:
      passwd_start_line = current_line;
      break;
    }
  }
  fclose(file);
  return passwd_start_line;
}

bool decrypt_password(const char *conf_file, const char *conf_name, const char *kdbx_file,
    int passwd_start_line, char *decrypted_passwd, size_t buf_size) {
  g_assert(decrypted_passwd != NULL && buf_size >= 8);

  char decrypt_cmd[256];
  snprintf(decrypt_cmd, sizeof(decrypt_cmd),
      "tail '-n+%d' '%s' | systemd-creds '--name=%s' decrypt - -", passwd_start_line, conf_file,
      conf_name);
  FILE *pipe = popen(decrypt_cmd, "r");
  if (!pipe) {
    g_warning("Failed to run systemd-creds for decryption: %s", STR_ERROR);
    return false;
  }
  size_t bytes_read = fread(decrypted_passwd, 1, buf_size, pipe);
  pclose(pipe);
  if (bytes_read == buf_size) {
    g_warning("Password for '%s' exceeds %lu characters!", kdbx_file, buf_size - 1);
    return false;
  } else if (bytes_read == 0) {
    g_warning("Failed to decrypt password using systemd-creds: %s", STR_ERROR);
    return false;
  }
  decrypted_passwd[bytes_read] = '\0';
  return true;
}

gchar *get_session_bus_address(GDBusConnection *system_conn, const gchar *scope) {
  if (!scope) return NULL;
  // get the processes under this systemd scope unit, traverse them and return the first
  // `DBUS_SESSION_BUS_ADDRESS` found
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) result = g_dbus_connection_call_sync(system_conn, "org.freedesktop.systemd1",
      "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "GetUnitProcesses",
      g_variant_new("(s)", scope), NULL, G_DBUS_CALL_FLAGS_NONE, DBUS_CALL_WAIT, NULL, &error);
  if (!result) {
    g_warning(
        "Failed to get processes for unit '%s': %s", scope, error ? error->message : "(null)");
    return NULL;
  }

  g_autoptr(GVariantIter) iter = NULL;
  g_variant_get(result, "(a(sus))", &iter);
  guint32 current_pid = 0;
  gchar *bus_address = NULL;
  while (g_variant_iter_next(iter, "(sus)", NULL, &current_pid, NULL)) {
    if ((bus_address = get_process_env_var(current_pid, "DBUS_SESSION_BUS_ADDRESS")) != NULL) {
      break;
    }
  }
  return bus_address;
}
