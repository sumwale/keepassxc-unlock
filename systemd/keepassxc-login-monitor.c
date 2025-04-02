#include <gio/gio.h>

#include "keepassxc-unlock-common.h"

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
  g_variant_get(parameters, "(so)", NULL, &session_path);

  // check if the session can be a target for auto-unlock and also get the owner
  print_info(
      "Checking if session '%s' can be auto-unlocked and looking up its owner\n", session_path);
  guint32 user_id = 0;
  bool session_valid = session_valid_for_unlock(conn, session_path, &user_id);
  g_free(session_path);
  if (!session_valid) {
    print_info("Ignoring session which is not a valid target for auto-unlock\n");
    return;
  }

  // check if the user has any databases configured for auto-unlock
  if (!user_has_db_configs(user_id)) {
    print_error(
        "Ignoring session as no KDBX databases have been configured for auto-unlock for UID=%u\n",
        user_id);
    return;
  }

  // start the systemd service for the user which gets instantiated from the template service
  char service_cmd[1024];
  snprintf(
      service_cmd, sizeof(service_cmd), "systemctl start keepassxc-unlock@%u.service", user_id);
  print_info("Executing: %s\n", service_cmd);
  if (system(service_cmd) != 0) {
    print_error(
        "\033[1;33mhandle_users_and_sessions() failed to start '%s': \033[00m", service_cmd);
    perror(NULL);
  }
}


int main(int argc, char *argv[]) {
  if (argc != 1) {
    print_error("No arguments are expected");
    return 1;
  }
  if (geteuid() != 0) {
    print_error("This program must be run as root\n");
    return 1;
  }

  print_info("Starting %s version %s\n", argv[0], PRODUCT_VERSION);

  // connect to the system bus
  GError *error = NULL;
  GDBusConnection *connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
  if (!connection) {
    print_error("Failed to connect to system bus: %s\n", error ? error->message : "(null)");
    g_clear_error(&error);
    return 1;
  }

  // subscribe to `SessionNew` signal on org.freedesktop.login1
  guint subscription_id = g_dbus_connection_signal_subscribe(connection,
      LOGIN_OBJECT_NAME,          // sender
      LOGIN_MANAGER_INTERFACE,    // interface
      "SessionNew",               // signal name
      LOGIN_OBJECT_PATH,          // object path
      NULL, G_DBUS_SIGNAL_FLAGS_NONE, handle_new_session, NULL, NULL);
  if (subscription_id == 0) {
    print_error("Failed to subscribe to receive D-Bus signals for %s\n", LOGIN_OBJECT_PATH);
    g_object_unref(connection);
    return 1;
  }

  // run the main loop
  GMainLoop *loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(loop);

  // cleanup
  g_dbus_connection_signal_unsubscribe(connection, subscription_id);
  g_object_unref(connection);
  g_main_loop_unref(loop);

  return 0;
}
