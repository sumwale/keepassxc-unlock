#include <glob.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

bool user_has_db_configs(guint32 user_id) {
  char conf_pattern[128];
  glob_t globbuf;

  // construct the configuration directory and pattern
  snprintf(conf_pattern, sizeof(conf_pattern), "%s/%u/*.conf", KP_CONFIG_DIR, user_id);

  // check if there are any configuration files in the user-specific configuration directory
  bool has_configs = glob(conf_pattern, 0, NULL, &globbuf) == 0 && globbuf.gl_pathc > 0;
  globfree(&globbuf);
  return has_configs;
}

bool session_valid_for_unlock(GDBusConnection *connection, const gchar *session_path,
    guint32 check_uid, guint32 *out_uid_ptr, bool *is_wayland_ptr, gchar **display_ptr) {
  GError *error = NULL;
  // get all properties of the session
  GVariant *session_props = g_dbus_connection_call_sync(connection, LOGIN_OBJECT_NAME, session_path,
      "org.freedesktop.DBus.Properties", "GetAll",
      g_variant_new("(s)", "org.freedesktop.login1.Session"), NULL, G_DBUS_CALL_FLAGS_NONE,
      DBUS_CALL_WAIT, NULL, &error);
  if (!session_props) {
    print_error(
        "Failed to get properties for '%s': %s\n", session_path, error ? error->message : "(null)");
    g_clear_error(&error);
    return false;
  }

  // parse the properties to check if the session is valid
  GVariantIter *iter = NULL;
  g_variant_get(session_props, "(a{sv})", &iter);

  bool user_match = false, has_supported_type = false, is_remote = false, is_active = false;
  const char *key = NULL;
  GVariant *value = NULL;
  while (g_variant_iter_loop(iter, "{&sv}", &key, &value)) {
    if (g_strcmp0(key, "User") == 0) {
      user_match = true;
      guint32 user_id = 0;
      g_variant_get(value, "(uo)", &user_id, NULL);
      if (out_uid_ptr) {
        *out_uid_ptr = user_id;
      } else if (check_uid != user_id) {
        print_error("Session not valid due to mismatch in given user ID %u from actual owner %u\n",
            check_uid, user_id);
        user_match = false;
      }
    } else if (g_strcmp0(key, "Display") == 0) {
      if (display_ptr) g_variant_get(value, "s", display_ptr);
    } else if (g_strcmp0(key, "Remote") == 0) {
      is_remote = g_variant_get_boolean(value);
    } else if (g_strcmp0(key, "Type") == 0) {
      const char *type_val = g_variant_get_string(value, NULL);
      bool is_wayland = g_strcmp0(type_val, "wayland") == 0;
      has_supported_type = is_wayland || g_strcmp0(type_val, "x11") == 0;
      if (has_supported_type && is_wayland_ptr) *is_wayland_ptr = is_wayland;
    } else if (g_strcmp0(key, "Active") == 0) {
      is_active = g_variant_get_boolean(value);
    }
  }
  g_variant_iter_free(iter);
  g_variant_unref(session_props);

  // a session is a target for auto-unlock if it is of a supported type, not remote, and active
  if (user_match && has_supported_type && !is_remote && is_active) {
    return true;
  } else {
    if (display_ptr && *display_ptr) g_free(*display_ptr);
    return false;
  }
}

gchar *get_process_env_var(guint32 pid, const char *env_var) {
  gchar env_file[128];
  snprintf(env_file, sizeof(env_file), "/proc/%u/environ", pid);

  // since the size of initial process environment is limited to ARG_MAX, its safe to read the
  // entire file in one go
  gchar *env = NULL;
  gsize env_len = 0;
  GError *error = NULL;
  if (!g_file_get_contents(env_file, &env, &env_len, &error)) {
    print_error("Failed to read file '%s': %s\n", env_file, error ? error->message : "(null)");
    g_clear_error(&error);
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
  g_free(env);
  return var_value;
}
