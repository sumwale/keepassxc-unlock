#ifndef _KEEPASSXC_UNLOCK_COMMON_H_
#define _KEEPASSXC_UNLOCK_COMMON_H_


#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gio/gio.h>

// PRODUCT_VERSION should be defined by build scripts
#ifndef PRODUCT_VERSION
  #define PRODUCT_VERSION ""
#endif

#define DBUS_MAIN_OBJECT_NAME "org.freedesktop.DBus"
#define LOGIN_OBJECT_NAME "org.freedesktop.login1"
#define LOGIN_OBJECT_PATH "/org/freedesktop/login1"
#define LOGIN_MANAGER_INTERFACE "org.freedesktop.login1.Manager"
#define DBUS_CALL_WAIT 60000    // in milliseconds

#define KP_CONFIG_DIR "/etc/keepassxc-unlock"
#define KP_CONFIG_PREFIX "kdbx-"
#define KP_DBUS_INTERFACE "org.keepassxc.KeePassXC.MainWindow"

// maximum allowed password size including terminating null;
// uses the same limit as glibc `getpass()` (see `man getpass`)
#define MAX_PASSWORD_SIZE BUFSIZ
#define MAX_TRIES 3
#define STR_ERROR g_strerror(errno)


/// @brief Connect to the global system or user's session D-Bus. Optionally display error on
///        `stderr` if there was a connection failure.
/// @param system_bus if `true` then connect to the system bus else to the user's session bus
/// @param log_error if `true` then log connection error to `stderr`
/// @return pointer to an instance of `GDBusConnection` that may be shared among callers, or NULL if
///         the connection was unsuccessful; the returned result must be released with
///         `g_object_unref()` after use
extern GDBusConnection *dbus_connect(bool system_bus, bool log_error);

/// @brief Change the effective user ID to the given one with error checking.
///        Exit the whole program with code 1 if it fails to change effective UID back to 0.
/// @param uid the user ID to be set as the effective UID
extern void change_euid(uid_t uid);

/// @brief Connect to the user's session D-Bus while switching effective user ID. Optionally display
///        error on `stderr` if there was a connection failure.
/// @param user_id the numeric ID of the user to switch the effective user ID for session connect to
///                be successful; the effective user ID will be switched back to root at the end
/// @param log_error if `true` then log connection error to `stderr`
/// @return pointer to an instance of `GDBusConnection` that may be shared among callers, or NULL if
///         the connection was unsuccessful; the returned result must be released with
///         `g_object_unref()` after use
extern GDBusConnection *dbus_session_connect(uid_t user_id, bool log_error);

/// @brief Check whether a user has configured KDBX database(s) for auto-unlock.
/// @param user_id the numeric ID of the user
/// @return `true` if user has at least one KDBX database configured for auto-unlock else `false`
extern bool user_has_db_configs(guint32 user_id);

/// @brief Check if auto-unlock should be attempted for a session with given path
///        (of the form `/org/freedesktop/login1/session/...`). The checks performed include
///        the type which must be `x11` or `wayland`, should be active and should not be remote.
/// @param system_conn the `GBusConnection` object for the system D-Bus
/// @param session_path path of the session to check
/// @param check_uid check this against the session owner's numeric ID if `out_uid_ptr` is NULL
/// @param out_uid_ptr pointer to `guint32` which is filled with session owner's user ID if non-NULL
/// @param is_wayland_ptr pointer to `bool` which (if non-NULL) is filled with `true` when session
///                       type is `wayland` else with `false` when it is `x11`
/// @param display_ptr pointer to `gchar*` string that is filled with the value of `Display`
///                    property if non-NULL; this should be released with `g_free()` after use or if
///                    the method failed returning `false`
/// @param scope_ptr pointer to `gchar*` string that is filled with the value of `Scope`
///                  property if non-NULL; this should be released with `g_free()` after use or if
///                  the method failed returning `false`
/// @return `true` if auto-unlock can be attempted for the session else `false`
extern bool session_valid_for_unlock(GDBusConnection *system_conn, const gchar *session_path,
    guint32 check_uid, guint32 *out_uid_ptr, bool *is_wayland_ptr, gchar **display_ptr,
    gchar **scope_ptr);

/// @brief Get value of an environment variable for a given process.
/// @param pid the ID of the process
/// @param env_var the environment variable to be read
/// @return value of the environment variable which should be released with `g_free()` after use,
///         else NULL in case of an error or if the variable was not found
extern gchar *get_process_env_var(guint32 pid, const char *env_var);

/// @brief Get the process ID registered for given D-Bus API on the session bus.
///        Since this uses the session bus, the call should be done after changing
///        the effective UID of this process to the target user.
/// @param session_conn the `GBusConnection` object for the user's session D-Bus
/// @param dbus_api the D-Bus API that the process has registered
/// @return the process ID registered for the D-Bus API or 0 if something went wrong
extern guint32 get_dbus_service_process_id(GDBusConnection *session_conn, const char *dbus_api);

/// @brief Calculate the SHA-512 hash for the given file and return as a hexadecimal string.
///        Note: this implementation of SHA-512 calculation is based on `glib` functions and is
//         2-2.5X slower than OpenSSL's implementation for large files but the overall time is
///        still minuscule for a small file like keepassxc executable and it avoids having to add
///        an OpenSSL dependency just for SHA-512 checksum.
/// @param path path of the file for which SHA-512 hash has to be calculated
/// @return SHA-512 hash as a hexadecimal string which should be free'd with `g_free()` after use,
///         or NULL on failure
extern gchar *sha512sum(const char *path);

/// @brief Read keepassxc-unlock user's KDBX database configuration file that has encrypted password
///        and key file path.
/// @param conf_file the keepassxc-unlock configuration file
/// @param kdbx_file pointer to the KDBX file name string that will be filled with a dynamically
///                  allocated value; the return value must be released with `g_free()` after use
///                  or if the method failed returning -1
/// @param key_file pointer to the key file name string that will be filled with a dynamically
///                 allocated value; the return value must be released with `g_free()` after use
///                 or if the method failed returning -1
/// @return the line number at which the encrypted password starts in the file, or -1 on error
///          (failures are logged using glib routines)
extern int read_configuration_file(const char *conf_file, gchar **kdbx_file, gchar **key_file);

/// @brief Decrypt password recorded in keepassxc-unlock configuration file for a KDBX database.
/// @param conf_file the configuration file for a KDBX database
/// @param conf_name name of the configuration used for encryption (usually the name of file without
///                  the `.conf` suffix and `kdbx-` suffix)
/// @param kdbx_file the path of the KDBX database file
/// @param passwd_start_line line number in the KDBX database file where the password starts
///                          (normally the result of a previous `read_configuration_file()` call)
/// @param decrypted_passwd buffer that will hold the decrypted password; cannot be NULL
/// @param buf_size total size of the `decrypted_passwd` buffer; this should be at least 8
/// @return `true` if the decryption was successful, `false` otherwise
///          (failures are logged using glib routines)
extern bool decrypt_password(const char *conf_file, const char *conf_name, const char *kdbx_file,
    int passwd_start_line, char *decrypted_passwd, size_t buf_size);

/// @brief Get the value of `DBUS_SESSION_BUS_ADDRESS` environment variable from the environment of
///        the processes belonging to the given `Scope`. The value from the last process in the list
///        having the variable set is used.
/// @param system_conn the `GBusConnection` object for the system D-Bus
/// @param scope the `Scope` where the `DBUS_SESSION_BUS_ADDRESS` has to be searched
/// @return the value of the `DBUS_SESSION_BUS_ADDRESS` environment variable from the last process
///         in the given scope, or NULL if no process has a setting for the variable
extern gchar *get_session_bus_address(GDBusConnection *system_conn, const gchar *scope);


#endif /* !_KEEPASSXC_UNLOCK_COMMON_H_ */
