#include "common.h"

#include <ctype.h>
#include <pwd.h>
#include <readline/readline.h>
#include <sys/stat.h>
#include <termios.h>


/// @brief Show usage of this program.
/// @param script_name name of the invoking script as obtained from `argv[0]`
static void show_usage(const char *script_name) {
  g_print("\nUsage: %s [--version] <USER> <KDBX>\n", script_name);
  g_print("\nSetup keepassxc-unlock password and key for a specified user's KDBX database\n");
  g_print("\nArguments:\n");
  g_print("  --version       show the version string and exit\n\n");
  g_print("  <USER>          name of the user who owns the database\n");
  g_print("  <KDBX>          path to the KDBX database (can be relative or absolute)\n\n");
}

/// @brief Prompt and read password from standard input without echo.
/// @param passwd input buffer which will be filled in with the password entered; should be a static
///               buffer of size `MAX_PASSWORD_SIZE + 1`
/// @param prompt the prompt to be displayed when asking for the password
/// @return `true` if the password was succesfully obtained, `false` otherwise
static bool get_password(char passwd[MAX_PASSWORD_SIZE + 1], const gchar *prompt) {
  struct termios old_term, new_term;
  g_print("%s", prompt);
  // save old settings to restore at the end
  tcgetattr(STDIN_FILENO, &old_term);
  new_term = old_term;
  // set no echo
  new_term.c_lflag &= (tcflag_t)~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
  // read upto MAX_PASSWORD_SIZE-1 characters excluding the newline
  passwd[MAX_PASSWORD_SIZE - 1] = '\0';
  if (!fgets(passwd, MAX_PASSWORD_SIZE + 1, stdin)) {
    g_printerr("Failed to read password\n");
    return false;
  }
  passwd[strcspn(passwd, "\n")] = '\0';
  // reset terminal
  tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
  g_print("\n");
  if (*passwd == '\0') return false;    // password cannot be empty
  if (passwd[MAX_PASSWORD_SIZE - 1] != '\0') {
    g_printerr("Password exceeds the limit of %d characters!\n", MAX_PASSWORD_SIZE - 1);
    return false;
  }
  return true;
}

/// @brief Prompt user to enter the password without echo, with repeat entry for confirmation.
///        Repeats `MAX_TRIES` times until successful.
/// @param passwd input buffer which will be filled in with the password entered; should be a static
///               buffer of size `MAX_PASSWORD_SIZE + 1`
/// @return `true` if the password was succesfully obtained, `false` otherwise
static bool read_password(char passwd[MAX_PASSWORD_SIZE + 1]) {
  char passwd2[MAX_PASSWORD_SIZE + 1];
  for (int i = 0; i < MAX_TRIES; i++) {
    if (!get_password(passwd, "Enter the password for the database: ")) continue;
    if (!get_password(passwd2, "Type the password again: ")) continue;
    if (strcmp(passwd, passwd2) == 0) {
      return true;
    } else {
      g_printerr("Passwords do not match\n");
    }
  }
  g_printerr("Maximum number of tries exhausted\n");
  return false;
}

/// @brief Ask the user to input the key file for the KDBX database using `readline()` for easy
///        editing and <TAB> completion.
/// @return the resolved file name with and `~`s expanded, empty string for no key file, or NULL for
///         error; release with `free()`/`g_free()` after use
static char *read_key_file_path() {
  for (int i = 0; i < MAX_TRIES; i++) {
    g_autofree char *input = readline("Enter the key file for the database (empty for none, "
                                      "use <TAB> for file name completion): ");
    if (!input) {
      g_printerr("Error reading input\n");
      continue;
    }
    char *expanded = tilde_expand_word(g_strstrip(input));
    if (!expanded) {
      g_printerr("Error in tilde expansion of input\n");
      continue;
    }
    if (*expanded == '\0' || access(expanded, F_OK) == 0) {
      return expanded;
    } else {
      g_printerr("Cannot access file '%s': %s\n", expanded, STR_ERROR);
      free(expanded);
    }
  }
  g_printerr("Maximum number of tries exhausted\n");
  return NULL;
}

/// @brief Wait for the user to press the <Enter> key ignoring any prior input prior.
static void wait_for_enter() {
  fflush(stdout);
  g_autofree char *dummy = NULL;
  size_t sz = 0;
  if (getline(&dummy, &sz, stdin) <= 0) return;    // if...return to avoid compiler warning
  g_print("\n");
}

/// @brief Search for the session D-Bus, communicate with KeePassXC process on the bus, then try
///        unlocking the database with given password and key file, and record the SHA-512 checksum
///        of the keepassxc process after user confirmation.
/// @param user_id the numeric ID of the user
/// @param kdbx_file path of the KDBX database file
/// @param password the password (in plain-text) to unlock the database
/// @param key_file path of the key file required to unlock the database, can be empty
/// @return the SHA-512 hash of the keepassxc executable verified by the user as being the correct
///         one, or NULL on error; must be released with `g_free()` after use
static gchar *verify_and_compute_checksum(
    uid_t user_id, const char *kdbx_file, const char *password, const char *key_file) {
  // determine the `DBUS_SESSION_BUS_ADDRESS` by searching process environments in user sessions
  g_autoptr(GDBusConnection) system_conn = dbus_connect(true, true);
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) result = g_dbus_connection_call_sync(system_conn, LOGIN_OBJECT_NAME,
      LOGIN_OBJECT_PATH, LOGIN_MANAGER_INTERFACE, "ListSessions", NULL, NULL,
      G_DBUS_CALL_FLAGS_NONE, DBUS_CALL_WAIT, NULL, &error);
  if (!result) {
    g_printerr("Failed to list sessions: %s\n", error ? error->message : "(null)");
    return NULL;
  }

  g_autofree gchar *session_dbus_address = NULL;
  g_autoptr(GVariantIter) iter = NULL;
  g_variant_get(result, "(a(susso))", &iter);
  guint32 uid = 0;
  gchar *session_path = NULL;
  // pick the first valid user session that has `DBUS_SESSION_BUS_ADDRESS` set
  while (g_variant_iter_next(iter, "(suss&o)", NULL, &uid, NULL, NULL, &session_path)) {
    if (uid != user_id) continue;

    // get the session `Type`, `Display` and `Scope` properties
    g_autofree gchar *display = NULL;
    g_autofree gchar *scope = NULL;
    bool is_wayland = false;
    if (!session_valid_for_unlock(
            system_conn, session_path, user_id, NULL, &is_wayland, &display, &scope)) {
      continue;
    }

    // get the session dbus address
    if ((session_dbus_address = get_session_bus_address(system_conn, scope)) != NULL) break;
  }
  // fallback to default if `DBUS_SESSION_BUS_ADDRESS` is not set for any process of user sessions
  if (!session_dbus_address) {
    g_printerr("Failed to find DBUS_SESSION_BUS_ADDRESS in the environment of any of the processes "
               "in open sessions of the user (ID=%u). Falling back to the default value.\n",
        user_id);
    session_dbus_address = g_strdup_printf("unix:path=/run/user/%u/bus", user_id);
  }
  setenv("DBUS_SESSION_BUS_ADDRESS", session_dbus_address, 1);

  g_autoptr(GDBusConnection) session_conn = dbus_session_connect(user_id, true);
  g_print("\nVerifying the given parameters. Please ensure KeePassXC is running and lock the "
          "database '%s'\nHit <Enter> to continue.",
      kdbx_file);

  gchar *kp_sha512 = NULL;
  for (int i = 0; i < MAX_TRIES; i++) {
    wait_for_enter();
    // get the keepassxc process ID using the D-Bus API
    guint32 kp_pid = get_dbus_service_process_id(session_conn, KP_DBUS_INTERFACE);
    if (kp_pid == 0) {
      g_print("Could not communicate with a running instance of KeePassXC "
              "(DBUS_SESSION_BUS_ADDRESS = %s)\nHit <Enter> to retry.",
          session_dbus_address);
      continue;
    }
    // get the link to the keepassxc process executable from /proc
    char kp_exe[128];
    snprintf(kp_exe, sizeof(kp_exe), "/proc/%u/exe", kp_pid);
    g_autofree const gchar *kp_exe_full = g_file_read_link(kp_exe, NULL);
    const gchar *kp_exe_real = kp_exe_full ? kp_exe_full : kp_exe;
    g_print("Will try to unlock the database for process with ID %u, executable %s\nHit <Enter> "
            "to send the password and key to this process, else press <Ctrl-c> to abort now.",
        kp_pid, kp_exe_real);
    wait_for_enter();
    g_autoptr(GVariant) result = g_dbus_connection_call_sync(session_conn, KP_DBUS_INTERFACE,
        "/keepassxc", KP_DBUS_INTERFACE, "openDatabase",
        g_variant_new("(sss)", kdbx_file, password, key_file), NULL, G_DBUS_CALL_FLAGS_NONE,
        DBUS_CALL_WAIT, NULL, &error);
    if (!result) {
      g_printerr("Failed to unlock the database: %s.\nHit <Enter> to retry.",
          error ? error->message : "(null)");
      continue;
    }

    g_print("Was the database unlocked successfully? (y/N) ");
    fflush(stdout);
    g_autofree char *response = NULL;
    size_t sz = 0;
    if (getline(&response, &sz, stdin) < 2 || tolower(*response) != 'y') {
      g_printerr("Some error with the given parameters, please register again\n");
      return NULL;
    }
    if ((kp_sha512 = sha512sum(kp_exe)) != NULL) break;
  }
  if (!kp_sha512) {
    g_printerr("Maximum tries exhausted. Unable to register a valid instance of KeePassXC.\n");
  }
  return kp_sha512;
}

/// @brief Encrypt the password using systemd-creds and append it to the configuration file.
/// @param password the password (in plain-text) to encrypt
/// @param conf_file the configuration file to which the encrypted password will be appended
/// @param conf_name the configuration name
/// @param key_type the key type for encryption
/// @return `true` if the append was successful, `false` otherwise
static bool append_encrypted_password(
    const char *password, const char *conf_file, const char *conf_name, const char *key_type) {
  // the encrypted password will be appended to `conf_file`
  char command[512];
  snprintf(command, sizeof(command), "systemd-creds --name=%s --with-key=%s encrypt - - >> '%s'",
      conf_name, key_type, conf_file);

  // open a pipe to the command and write the password which will be encrypted by `systemd-creds`
  FILE *pipe = popen(command, "w");
  if (!pipe) {
    g_printerr("Failed to execute systemd-creds: %s\n", STR_ERROR);
    return false;
  }
  // write to the pipe and check for errors
  bool failed = fputs(password, pipe) == EOF;
  if (failed) g_printerr("Failed to write password to systemd-creds: %s\n", STR_ERROR);
  if (pclose(pipe) != 0) {
    g_printerr("Failure in systemd-creds command\n");
    failed = true;
  }
  return !failed;
}

/// @brief Write a new configuration file, or overwrite existing one with given parameters.
/// @param conf_file path of the configuration file
/// @param conf_name name of the configuration, usually the base name of `conf_file`
///                  without prefix and suffix
/// @param kdbx_file path of the KDBX database file
/// @param key_file path of the key file required to unlock the database, can be empty
/// @param password the password (in plain-text) to unlock the database
/// @param key_type type of the key to use for encryption, one of "host" or "host+tpm2"
/// @return `true` if the configuration file was successfully written, `false` otherwise
static bool write_configuration_file(const char *conf_file, const char *conf_name,
    const char *kdbx_file, const char *key_file, const char *password, const char *key_type) {
  FILE *conf_fp = fopen(conf_file, "w");
  if (!conf_fp) {
    fprintf(stderr, "Failed to open configuration file '%s': %s\n", conf_file, STR_ERROR);
    return false;
  }
  if (fprintf(conf_fp, "DB=%s\nKEY=%s\nPASSWORD:\n", kdbx_file, key_file) <= 0) {
    fclose(conf_fp);
    g_printerr("Failed to write fields to the configuration: %s\n", STR_ERROR);
    unlink(conf_file);
    return false;
  }
  fclose(conf_fp);
  // encrypt the password and append to the configuration file
  if (password && !append_encrypted_password(password, conf_file, conf_name, key_type)) {
    g_printerr("Failed to write encrypted password to the configuration\n");
    unlink(conf_file);
    return false;
  }
  return true;
}

/// @brief Temporary code for upgrading pre 0.9.6 configuration files.
/// @param old_conf_file path to the old configuration file
/// @return exit code for the upgrade process
static int handle_pre096_upgrade(const char *old_conf_file) {
  g_autofree const char *old_conf_path = realpath(old_conf_file, NULL);
  g_autofree gchar *kdbx_file = NULL;
  g_autofree gchar *key_file = NULL;

  const char *old_conf_filename = strrchr(old_conf_path, '/');
  if (old_conf_filename == NULL) {
    g_printerr("Need full path for configuration file '%s'\n", old_conf_path);
    return 1;
  }
  int passwd_start_line = read_configuration_file(old_conf_path, &kdbx_file, &key_file);
  if (passwd_start_line == -1) return 1;

  char conf_file[200], command[1024];
  g_autofree gchar *conf_name = g_compute_checksum_for_string(G_CHECKSUM_SHA256, kdbx_file, -1);
  // `old_conf_filename - old_conf_file` gives the length of directory portion of `old_conf_file`
  snprintf(conf_file, sizeof(conf_file), "%.*s/" KP_CONFIG_PREFIX "%s.conf",
      (int)(old_conf_filename - old_conf_path), old_conf_path, conf_name);
  if (!write_configuration_file(conf_file, conf_name, kdbx_file, key_file, NULL, NULL)) return 1;

  // decrypt reading from old configuration file and append encrypted password using command pipes
  snprintf(command, sizeof(command),
      "tail '-n+%d' '%s' | systemd-creds --name= decrypt - - | systemd-creds --with-key=auto "
      "'--name=%s' encrypt - - >> '%s'",
      passwd_start_line, old_conf_path, conf_name, conf_file);
  int exit_code = system(command);
  if (exit_code == 0) {
    g_print("Successfully upgraded old configuration '%s'\n", old_conf_path);
  } else {
    g_printerr(
        "Failed to re-encrypt password reading from old configuration '%s'\n", old_conf_path);
    unlink(conf_file);
  }
  return exit_code;
}


int main_setup(int argc, char *argv[]) {
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    g_print("%s\n", PRODUCT_VERSION);
    return 0;
  }
  if (geteuid() != 0) {
    g_printerr("This program must be run as root\n");
    return 1;
  }
  if (argc != 3) {
    show_usage(argv[0]);
    return 1;
  }

  // temporary internal flag for upgrade from pre 0.9.6 releases
  if (strcmp(argv[1], "--upgrade") == 0) return handle_pre096_upgrade(argv[2]);

  // resolve user ID
  const char *user_name = argv[1];
  struct passwd *pwd = getpwnam(user_name);
  if (!pwd) {
    g_printerr("Invalid user: %s\n", user_name);
    return 2;
  }
  uid_t user_id = pwd->pw_uid;

  g_print("Running %s version %s\n\n", argv[0], PRODUCT_VERSION);

  // ensure that only system paths are searched for all the utilities
  setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin", true);

  // resolve KDBX file path
  const char *kdbx_path = argv[2];
  g_autofree const gchar *kdbx_file = realpath(kdbx_path, NULL);
  if (!kdbx_file || access(kdbx_file, F_OK) != 0) {
    g_printerr("KDBX database '%s' does not exist or is not a file\n", kdbx_path);
    return 1;
  }

  // check for TPM2 support
  const char *key_type = "host+tpm2";
  g_print("Checking TPM2 support\n\n");
  int exit_code = system("systemd-creds has-tpm2");
  g_print("\n");
  if (exit_code == 127) {    // shell could not find the command
    g_printerr("systemd-creds absent: minimum version of systemd required is 250\n");
    return 1;
  } else if (exit_code != 0) {
    g_print("\nSystem lacks TPM2 support. If only libraries are missing in the output above\n");
    g_print("then install the required TSS libraries and try again. Installing tpm2-tools\n");
    g_print("package should install all the required libraries.\n\n");
    g_print("WARNING: continuing can weaken security if the root filesystem is not encrypted.\n\n");
    g_print("Continue without TPM2 support? (y/N) ");
    fflush(stdout);
    g_autofree char *response = NULL;
    size_t sz = 0;
    if (getline(&response, &sz, stdin) < 2 || tolower(*response) != 'y') { return 0; }
    key_type = "host";
  }

  // set process umask to disallow permissions to group/others for any created directories/files
  umask(0077);

  // invoke setup if host specific credential file is absent
  if (access("/var/lib/systemd/credential.secret", F_OK) != 0) {
    if (system("systemd-creds setup") != 0) {
      g_printerr("Failed to generate host encryption key\n");
      return 1;
    }
  }

  // setup configuration path variables
  char user_conf_dir[100], conf_file[200], kp_sha512_file[128];
  snprintf(user_conf_dir, sizeof(user_conf_dir), "%s/%u", KP_CONFIG_DIR, user_id);
  g_autofree gchar *conf_name = g_compute_checksum_for_string(G_CHECKSUM_SHA256, kdbx_file, -1);
  snprintf(
      conf_file, sizeof(conf_file), "%s/" KP_CONFIG_PREFIX "%s.conf", user_conf_dir, conf_name);
  snprintf(kp_sha512_file, sizeof(kp_sha512_file), "%s/keepassxc.sha512", user_conf_dir);

  // create configuration directory
  if (g_mkdir_with_parents(user_conf_dir, 0700) != 0) {
    g_printerr("Failed to create configuration directory '%s': %s\n", user_conf_dir, STR_ERROR);
    return 1;
  }

  // check for existing configuration file
  char password[MAX_PASSWORD_SIZE + 1];
  g_autofree char *key_file = NULL;
  bool use_existing_conf = false;
  if (access(conf_file, F_OK) == 0) {
    g_print("Overwrite existing configuration for %s? (y/N) ", kdbx_file);
    fflush(stdout);
    g_autofree char *response = NULL;
    size_t sz = 0;
    if (getline(&response, &sz, stdin) < 2 || tolower(*response) != 'y') {
      // continue and update the SHA-512 of the executable, so read the existing values
      g_autofree gchar *recorded_kdbx_file = NULL;
      int passwd_start_line = read_configuration_file(conf_file, &recorded_kdbx_file, &key_file);
      if (passwd_start_line == -1) return 1;
      if (g_strcmp0(recorded_kdbx_file, kdbx_file) != 0) {
        g_printerr("Recorded KDBX file '%s' does not match the current '%s'!!\n",
            recorded_kdbx_file, kdbx_file);
        return 1;
      }
      if (!decrypt_password(
              conf_file, conf_name, kdbx_file, passwd_start_line, password, MAX_PASSWORD_SIZE)) {
        return 1;
      }
      use_existing_conf = true;
    }
  }

  if (!use_existing_conf) {
    // prompt for password with double check
    if (!read_password(password)) return 1;

    // prompt and read the key file path
    if ((key_file = read_key_file_path()) == NULL) return 1;
  }

  g_autofree gchar *kp_sha512 = verify_and_compute_checksum(user_id, kdbx_file, password, key_file);
  if (!kp_sha512) return 1;

  if (!use_existing_conf) {
    // write the configuration file
    g_print("Writing the parameters and encrypted password to the configuration file\n");
    if (!write_configuration_file(conf_file, conf_name, kdbx_file, key_file, password, key_type)) {
      return 1;
    }
  }
  chmod(conf_file, 0400);    // set final permissions

  // write the checksum file
  g_autoptr(GError) error = NULL;
  if (!g_file_set_contents_full(
          kp_sha512_file, kp_sha512, -1, G_FILE_SET_CONTENTS_CONSISTENT, 0400, &error)) {
    g_printerr("Failed to write SHA-512 checksum to '%s': %s\nPlease try again\n", kp_sha512_file,
        error ? error->message : "(null)");
    if (!use_existing_conf) unlink(conf_file);
    return 1;
  }

  g_print("Configuration saved successfully\n");
  return 0;
}
