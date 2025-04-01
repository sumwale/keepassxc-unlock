#ifndef _KEEPASSXC_UNLOCK_COMMON_H_
#define _KEEPASSXC_UNLOCK_COMMON_H_


#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gio/gio.h>

#define KP_CONFIG_DIR "/etc/keepassxc-unlock"

#define LOGIN_OBJECT_NAME "org.freedesktop.login1"
#define LOGIN_OBJECT_PATH "/org/freedesktop/login1"
#define LOGIN_MANAGER_INTERFACE "org.freedesktop.login1.Manager"
#define DBUS_CALL_WAIT 60000    // in milliseconds

#define print_info(...)                                                                            \
  {                                                                                                \
    printf(__VA_ARGS__);                                                                           \
    fflush(stdout);                                                                                \
  }
#define print_error(...)                                                                           \
  {                                                                                                \
    fprintf(stderr, __VA_ARGS__);                                                                  \
    fflush(stderr);                                                                                \
  }

/// @brief Check whether a user has configured KDBX database(s) for auto-unlock.
/// @param user_id the numeric ID of the user
/// @return `true` if user has at least one KDBX database configured for auto-unlock else `false`
extern bool user_has_db_configs(guint32 user_id);

/// @brief Check whether a user session can be a target for auto-unlock (`Type` is x11/wayland etc).
/// @param connection the `GBusConnection` object for the system D-Bus
/// @param session_path path of the session
/// @param user_id_ptr if set to non-NULL, then also fill in the numeric ID of the user that owns
///                    the session
/// @return `true` if session is a valid target for auto-unlock else `false`
extern bool session_valid_for_unlock(
    GDBusConnection *connection, const gchar *session_path, guint32 *user_id_ptr);


#endif /* !_KEEPASSXC_UNLOCK_COMMON_H_ */
