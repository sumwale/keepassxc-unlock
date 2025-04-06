#include <gio/gio.h>

#include "common.h"

/// @brief Callback for creation of a new session that checks if it is a valid target for auto-lock
///        and if so, then starts user-specific `keepassxc-unlock@<uid>.service` to handle the same.
/// @param conn the `GBusConnection` object for the system D-Bus
/// @param sender_name name of the sender of the event
/// @param object_path path of the object for which the event was raised
/// @param interface_name D-Bus interface of the raised signal
/// @param signal_name name of the D-Bus signal that was raised (should be `SessionNew`)
/// @param parameters parameters of the raised signal
/// @param user_data custom user data sent through with the event which is ignored for this method
void handle_new_session(GDBusConnection *conn, const gchar *sender_name, const gchar *object_path,
    const gchar *interface_name, const gchar *signal_name, GVariant *parameters,
    gpointer user_data) {
  gchar *session_path = NULL;
  // extract session path from the parameters
  g_variant_get(parameters, "(s&o)", NULL, &session_path);    // `&o` avoids `g_free()`

  // check if the session can be a target for auto-unlock and also get the owner
  g_message("Checking if session '%s' can be auto-unlocked and looking up its owner", session_path);
  guint32 user_id = 0;
  if (!session_valid_for_unlock(conn, session_path, 0, &user_id, NULL, NULL)) {
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

  // write session.env for the service (extension should not be `.conf` which is for kdbx configs)
  char session_env[128];
  snprintf(session_env, sizeof(session_env), "%s/%u/session.env", KP_CONFIG_DIR, user_id);
  FILE *session_env_fp = fopen(session_env, "w");
  if (!session_env_fp) {
    g_critical(
        "handle_new_session() failed to open '%s' for writing: %s", session_env, g_strerror(errno));
    return;
  }
  // this can write different session paths for the same user but it doesn't matter since subsequent
  // service starts for the same user will be ignored in any case (if the previous service is still
  //   running) and the existing one will keep performing auto-unlock for its session
  fprintf(session_env_fp, "SESSION_PATH=%s\n", session_path);
  fclose(session_env_fp);

  // start the systemd service for the user which gets instantiated from the template service
  char service_cmd[128];
  // deliberately have only one auto-unlock service for one user and not separate one for each
  // session to avoid those interfering with one another (KeePassXC instance to session correlation
  //   might be incorrect for multiple Wayland sessions)
  // TODO: use org.freedesktop.systemd1.Manager.StartUnit("...", "replace") API
  snprintf(
      service_cmd, sizeof(service_cmd), "systemctl start keepassxc-unlock@%u.service", user_id);
  g_message("Executing: %s", service_cmd);
  if (system(service_cmd) != 0) {
    g_critical("handle_new_session() failed to start '%s': %s", service_cmd, g_strerror(errno));
  }
}


int main(int argc, char *argv[]) {
  if (geteuid() != 0) {
    g_printerr("This program must be run as root\n");
    return 1;
  }
  // TODO: add --version argument to this
  if (argc != 1) {
    g_printerr("No arguments are expected\n");
    return 1;
  }

  g_print("Starting %s version %s\n", argv[0], PRODUCT_VERSION);

  // connect to the system bus
  g_autoptr(GDBusConnection) connection = dbus_connect(true, true);
  if (!connection) return 1;

  // subscribe to `SessionNew` signal on org.freedesktop.login1
  guint subscription_id = g_dbus_connection_signal_subscribe(connection,
      LOGIN_OBJECT_NAME,          // sender
      LOGIN_MANAGER_INTERFACE,    // interface
      "SessionNew",               // signal name
      LOGIN_OBJECT_PATH,          // object path
      NULL, G_DBUS_SIGNAL_FLAGS_NONE, handle_new_session, NULL, NULL);
  if (subscription_id == 0) {
    g_critical("Failed to subscribe to receive D-Bus signals for %s", LOGIN_OBJECT_PATH);
    return 1;
  }

  // run the main loop
  g_autoptr(GMainLoop) loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(loop);

  g_dbus_connection_signal_unsubscribe(connection, subscription_id);
  return 0;
}
