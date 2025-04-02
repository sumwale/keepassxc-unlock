#include <glob.h>
#include <sys/types.h>
#include <unistd.h>

#include "keepassxc-unlock-common.h"

/// @brief Check if the user with given ID has any KeePassXC database configured for auto-unlock.
/// @param user_id the ID of the user to check
/// @return `true` if user has any KeePassXC database configured for auto-unlock else `false`
bool user_has_db_configs(guint32 user_id) {
  char conf_pattern[128];
  glob_t globbuf;

  // construct the configuration directory and pattern
  snprintf(conf_pattern, sizeof(conf_pattern), "%s/%d/*.conf", KP_CONFIG_DIR, user_id);

  // check if there are any configuration files in the user-specific configuration directory
  bool has_configs = glob(conf_pattern, 0, NULL, &globbuf) == 0 && globbuf.gl_pathc > 0;
  globfree(&globbuf);
  return has_configs;
}

/// @brief Check if auto-unlock should be attempted for a session with given path
///        (of the form `/org/freedesktop/login1/session/...`). The checks performed include
///        the type which must be `x11` or `wayland`, should be active and should not be remote.
/// @param connection the `GBusConnection` object for the system D-Bus
/// @param session_path path of the session to check
/// @param user_id_ptr pointer to `guint32` which is filled with owner's user ID if non-NULL
/// @return `true` if auto-unlock can be attempted for the session else `false`
bool session_valid_for_unlock(
    GDBusConnection *connection, const gchar *session_path, guint32 *user_id_ptr) {
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

  bool user_found = false, has_supported_type = false, is_remote = false, is_active = false;
  const char *key = NULL;
  GVariant *value = NULL;
  while (g_variant_iter_loop(iter, "{&sv}", &key, &value)) {
    if (g_strcmp0(key, "User") == 0) {
      if (user_id_ptr != NULL) g_variant_get(value, "(uo)", user_id_ptr, NULL);
      user_found = true;
    } else if (g_strcmp0(key, "Type") == 0) {
      const char *type_val = g_variant_get_string(value, NULL);
      has_supported_type = g_strcmp0(type_val, "x11") == 0 || g_strcmp0(type_val, "wayland") == 0;
    } else if (g_strcmp0(key, "Remote") == 0) {
      is_remote = g_variant_get_boolean(value);
    } else if (g_strcmp0(key, "Active") == 0) {
      is_active = g_variant_get_boolean(value);
    }
  }
  g_variant_iter_free(iter);
  g_variant_unref(session_props);

  // a session is a target for auto-unlock if it is of a supported type, not remote, and active
  return user_found && has_supported_type && !is_remote && is_active;
}
