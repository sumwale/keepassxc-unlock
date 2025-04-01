#include <glob.h>
#include <sys/types.h>
#include <unistd.h>

#include "keepassxc-unlock-common.h"

bool user_has_db_configs(guint32 user_id) {
  char user_conf_dir[100], conf_pattern[128];
  glob_t globbuf;

  // construct the configuration directory and pattern
  snprintf(user_conf_dir, sizeof(user_conf_dir), "%s/%d", KP_CONFIG_DIR, user_id);
  snprintf(conf_pattern, sizeof(conf_pattern), "%s/*.conf", user_conf_dir);

  // check if there are any configuration files in the user-specific configuration directory
  bool has_configs = glob(conf_pattern, 0, NULL, &globbuf) == 0 && globbuf.gl_pathc > 0;
  globfree(&globbuf);
  return has_configs;
}

bool session_valid_for_unlock(GDBusConnection *connection, const gchar *session_path) {
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

  bool has_supported_type = false, is_remote = false, is_active = false;
  const char *key = NULL;
  GVariant *value = NULL;
  while (g_variant_iter_loop(iter, "{&sv}", &key, &value)) {
    if (g_strcmp0(key, "Type") == 0) {
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
  return has_supported_type && !is_remote && is_active;
}
