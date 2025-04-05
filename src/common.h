#ifndef _KEEPASSXC_UNLOCK_COMMON_H_
#define _KEEPASSXC_UNLOCK_COMMON_H_


#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gio/gio.h>

#define PRODUCT_VERSION "0.9.3"

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

/// @brief Connect to the global system or user's session D-Bus. Optionally display error on
///        `stderr` if there was a connection failure.
/// @param system_bus if `true` then connect to the system bus else to the user's session bus
/// @param log_error if `true` then log connection error to `stderr`
/// @return an instance of `GDBusConnection*` that may be shared among callers and must be released
///         using `g_object_unref()`, or NULL if the connection was unsuccessful
extern GDBusConnection *dbus_connect(bool system_bus, bool log_error);

/// @brief Check whether a user has configured KDBX database(s) for auto-unlock.
/// @param user_id the numeric ID of the user
/// @return `true` if user has at least one KDBX database configured for auto-unlock else `false`
extern bool user_has_db_configs(guint32 user_id);

/// @brief Check if auto-unlock should be attempted for a session with given path
///        (of the form `/org/freedesktop/login1/session/...`). The checks performed include
///        the type which must be `x11` or `wayland`, should be active and should not be remote.
/// @param connection the `GBusConnection` object for the system D-Bus
/// @param session_path path of the session to check
/// @param check_uid check this against the session owner's numeric ID if `out_uid_ptr` is NULL
/// @param out_uid_ptr pointer to `guint32` which is filled with session owner's user ID if non-NULL
/// @param is_wayland_ptr pointer to `bool` which (if non-NULL) is filled with `true` when session
///                       type is `wayland` else with `false` when it is `x11`
/// @param display_ptr pointer to `gchar*` string that is filled with the value of `Display`
///                    property if non-NULL; this should be released with `g_free()` after use
/// @return `true` if auto-unlock can be attempted for the session else `false`
extern bool session_valid_for_unlock(GDBusConnection *connection, const gchar *session_path,
    guint32 check_uid, guint32 *out_uid_ptr, bool *is_wayland_ptr, gchar **display_ptr);

/// @brief Get value of an environment variable for a given process.
/// @param pid the ID of the process
/// @param env_var the environment variable to be read
/// @return value of the environment variable which should be released with `g_free()` after use,
///         else NULL in case of an error or if the variable was not found
extern gchar *get_process_env_var(guint32 pid, const char *env_var);


#endif /* !_KEEPASSXC_UNLOCK_COMMON_H_ */
