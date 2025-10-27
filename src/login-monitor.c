#include "common.h"


static GMutex s_session_map_mutex;

/// @brief Convenience structure to hold session related data passed to dbus signal callbacks.
typedef struct {
  uid_t user_id;            // numeric ID of the user
  guint subscription_id;    // the subscription ID of a session's `PropertiesChanged` signals
} SessionData;

/// @brief Start a KeepassXC unlock service for a given session. The service runs as a separate
///        systemd service rather than a separate thread in the current service to allow for easy
///        management of the service, better resource separation among others.
/// @param system_conn the `GBusConnection` object for the system D-Bus
/// @param session_path path of the session for which the unlock service has to be started
/// @param user_id the numeric ID of the user
static void start_unlock_service(
    GDBusConnection *system_conn, const gchar *session_path, guint32 user_id);

static void tty_session_cleanup(GDBusConnection *system_conn, const gchar *session_path,
    GHashTable *session_map, bool trigger_unlock_svc) {
  g_mutex_lock(&s_session_map_mutex);
  const SessionData *session_data = (SessionData *)g_hash_table_lookup(session_map, session_path);
  if (session_data) {
    if (trigger_unlock_svc) start_unlock_service(system_conn, session_path, session_data->user_id);
    if (session_data->subscription_id) {
      g_dbus_connection_signal_unsubscribe(system_conn, session_data->subscription_id);
    }
    g_hash_table_remove(session_map, session_path);
  }
  g_mutex_unlock(&s_session_map_mutex);
}

/// @brief Callback to check for a non-graphical session switching to a valid graphical one, and if
///        so, starts user-specific `keepassxc-unlock@<uid>.service` to handle auto-unlock for it.
/// @param system_conn the `GBusConnection` object for the system D-Bus
/// @param sender_name name of the sender of the event
/// @param session_path path of the session for which the event was raised
/// @param interface_name D-Bus interface of the raised signal
/// @param signal_name name of the D-Bus signal that was raised (should be `PropertiesChanged`)
/// @param parameters parameters of the raised signal
/// @param user_data custom user data sent through with the event
static void on_session_properties_changed(GDBusConnection *system_conn, const gchar *sender_name,
    const gchar *session_path, const gchar *interface_name, const gchar *signal_name,
    GVariant *parameters, gpointer user_data) {
  g_autoptr(GVariantIter) iter = NULL;
  const gchar *key = NULL;
  GVariant *value = NULL;
  g_variant_get(parameters, "(sa{sv}as)", NULL, &iter, NULL);
  while (g_variant_iter_loop(iter, "{&sv}", &key, &value)) {
    if (g_strcmp0(key, "Type") == 0) {
      const gchar *type_val = g_variant_get_string(value, NULL);
      // start auto-unlock service for the session if it's type switched to a graphical one
      if (g_strcmp0(type_val, "wayland") == 0 || g_strcmp0(type_val, "x11") == 0) {
        tty_session_cleanup(system_conn, session_path, (GHashTable *)user_data, true);
      }
    }
  }
}

/// @brief Callback for creation of a new session that checks if it is a valid target for auto-lock
///        and if so, then starts user-specific `keepassxc-unlock@<uid>.service` to handle the same.
/// @param system_conn the `GBusConnection` object for the system D-Bus
/// @param sender_name name of the sender of the event
/// @param object_path path of the object for which the event was raised
/// @param interface_name D-Bus interface of the raised signal
/// @param signal_name name of the D-Bus signal that was raised (should be `SessionNew`)
/// @param parameters parameters of the raised signal
/// @param user_data custom user data sent through with the event which is ignored for this method
static void handle_new_session(GDBusConnection *system_conn, const gchar *sender_name,
    const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
    GVariant *parameters, gpointer user_data) {
  gchar *session_path = NULL;
  // extract session path from the parameters
  g_variant_get(parameters, "(s&o)", NULL, &session_path);    // `&o` avoids `g_free()`

  // check if the session can be a target for auto-unlock and also get the owner
  g_message("Checking if session '%s' can be auto-unlocked and looking up its owner", session_path);
  guint32 user_id = 0;
  int session_valid = 0;
  if ((session_valid = session_valid_for_unlock(
           system_conn, session_path, 0, &user_id, NULL, NULL, NULL)) == 0) {
    g_message("Ignoring session which is not a valid target for auto-unlock");
    return;
  }

  // check if the user has any databases configured for auto-unlock
  if (!user_has_db_configs(user_id)) {
    g_warning(
        "Ignoring session as no KDBX databases have been configured for auto-unlock by UID=%u",
        user_id);
    return;
  }

  if (session_valid != 1) {
    // subscribe to `PropertiesChanged` signal for the session
    GHashTable *session_map = (GHashTable *)user_data;
    SessionData *session_data = g_new(SessionData, 1);
    session_data->user_id = user_id;
    guint props_subscription_id = g_dbus_connection_signal_subscribe(system_conn,
        LOGIN_OBJECT_NAME,                    // sender
        "org.freedesktop.DBus.Properties",    // interface
        "PropertiesChanged",                  // signal name
        session_path,                         // object path
        NULL, G_DBUS_SIGNAL_FLAGS_NONE, on_session_properties_changed, session_map, NULL);
    session_data->subscription_id = props_subscription_id;
    if (props_subscription_id == 0) {
      g_warning("Failed to subscribe to receive D-Bus signals for PropertiesChanged of session %s",
          session_path);
      g_free(session_data);
    } else {
      // insert into the global map so that session close handler can cleanup if required
      g_mutex_lock(&s_session_map_mutex);
      // map session path to its data (key needs its own copy while data is owned by the map)
      g_hash_table_insert(session_map, g_strdup(session_path), session_data);
      g_mutex_unlock(&s_session_map_mutex);
    }
    return;
  }

  start_unlock_service(system_conn, session_path, user_id);
}

void start_unlock_service(
    GDBusConnection *system_conn, const gchar *session_path, guint32 user_id) {
  g_message("Starting unlock service for session '%s' UID=%u", session_path, user_id);

  // write session.env for the service (extension should not be `.conf` which is for kdbx configs)
  char session_env[128];
  snprintf(session_env, sizeof(session_env), "%s/%u/session.env", KP_CONFIG_DIR, user_id);
  FILE *session_env_fp = fopen(session_env, "w");
  if (!session_env_fp) {
    g_critical("handle_new_session() failed to open '%s' for writing: %s", session_env, STR_ERROR);
    return;
  }
  // this can write different session paths for the same user but it doesn't matter since subsequent
  // service starts for the same user will be ignored in any case (if the previous service is still
  //   running) and the existing one will keep performing auto-unlock for its session
  fprintf(session_env_fp, "SESSION_PATH=%s\n", session_path);
  fclose(session_env_fp);

  // start the systemd service for the user which gets instantiated from the template service
  char service_name[128];
  snprintf(service_name, sizeof(service_name), "keepassxc-unlock@%u.service", user_id);
  g_autoptr(GError) error = NULL;
  // send the `StartUnit` command to start the service (equivalent to `systemctl start ...`)
  g_autoptr(GVariant) result = g_dbus_connection_call_sync(system_conn, "org.freedesktop.systemd1",
      "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartUnit",
      g_variant_new("(ss)", service_name, "replace"), NULL, G_DBUS_CALL_FLAGS_NONE, DBUS_CALL_WAIT,
      NULL, &error);
  if (!result) {
    g_critical("handle_new_session() failed to start '%s': %s", service_name,
        error ? error->message : "(null)");
  }
}

/// @brief Callback to handle session close for the selected session.
static void handle_session_close(GDBusConnection *system_conn, const char *sender_name,
    const char *object_path, const char *interface_name, const char *signal_name,
    GVariant *parameters, gpointer user_data) {
  gchar *session_path = NULL;
  g_variant_get(parameters, "(s&o)", NULL, &session_path);    // `&o` avoids `g_free()`
  tty_session_cleanup(system_conn, session_path, (GHashTable *)user_data, false);
}


int main_monitor(int argc, char *argv[]) {
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    g_print("%s\n", PRODUCT_VERSION);
    return 0;
  }
  if (geteuid() != 0) {
    g_printerr("This program must be run as root\n");
    return 1;
  }
  if (argc != 1) {
    g_printerr("No arguments are expected apart from --version\n");
    return 1;
  }

  g_message("Starting %s version %s", argv[0], PRODUCT_VERSION);

  // connect to the system bus
  g_autoptr(GDBusConnection) connection = dbus_connect(true, true);
  if (!connection) return 1;

  // map to hold session data for each tty session being tracked for possible "upgrade"
  // to graphical session
  GHashTable *session_map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

  // subscribe to `SessionNew` signal on org.freedesktop.login1
  guint subscription_id = g_dbus_connection_signal_subscribe(connection,
      LOGIN_OBJECT_NAME,          // sender
      LOGIN_MANAGER_INTERFACE,    // interface
      "SessionNew",               // signal name
      LOGIN_OBJECT_PATH,          // object path
      NULL, G_DBUS_SIGNAL_FLAGS_NONE, handle_new_session, session_map, NULL);
  if (subscription_id == 0) {
    g_critical("Failed to subscribe to D-Bus 'SessionNew' signals for %s", LOGIN_OBJECT_PATH);
    g_hash_table_destroy(session_map);
    return 1;
  }
  // subscribe to `SessionRemoved` signal too in order to clear session data for tty logins
  guint session_rm_subscription_id = g_dbus_connection_signal_subscribe(connection,
      LOGIN_OBJECT_NAME,          // sender
      LOGIN_MANAGER_INTERFACE,    // interface
      "SessionRemoved",           // signal name
      LOGIN_OBJECT_PATH,          // object path
      NULL, G_DBUS_SIGNAL_FLAGS_NONE, handle_session_close, session_map, NULL);
  if (session_rm_subscription_id == 0) {
    g_critical("Failed to subscribe to D-Bus 'SessionRemoved' signals for %s", LOGIN_OBJECT_PATH);
    g_dbus_connection_signal_unsubscribe(connection, subscription_id);
    g_hash_table_destroy(session_map);
    return 1;
  }

  // run the main loop
  g_autoptr(GMainLoop) loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(loop);

  g_dbus_connection_signal_unsubscribe(connection, subscription_id);
  g_dbus_connection_signal_unsubscribe(connection, session_rm_subscription_id);
  g_hash_table_destroy(session_map);
  return 0;
}
