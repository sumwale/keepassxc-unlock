// entry point for multicall static binary

#include <stdio.h>
#include <string.h>

extern int main_monitor(int argc, char *argv[]);
extern int main_setup(int argc, char *argv[]);
extern int main_unlock(int argc, char *argv[]);

#define MONITOR_EXEC "keepassxc-login-monitor"
#define SETUP_EXEC "keepassxc-unlock-setup"
#define UNLOCK_EXEC "keepassxc-unlock"
#define ALL_EXEC "keepassxc-unlock-all"


int main(int argc, char *argv[]) {
  const char *exec_name = strrchr(argv[0], '/');
  if (exec_name) {
    exec_name++;
  } else {
    exec_name = argv[0];
  }
  if (strncmp(exec_name, ALL_EXEC, sizeof(ALL_EXEC) - 1) == 0) {
    fprintf(stderr, "Cannot directly invoke multicall binary\n");
    return 1;
  } else if (strncmp(exec_name, MONITOR_EXEC, sizeof(MONITOR_EXEC) - 1) == 0) {
    return main_monitor(argc, argv);
  } else if (strncmp(exec_name, SETUP_EXEC, sizeof(SETUP_EXEC) - 1) == 0) {
    return main_setup(argc, argv);
  } else if (strncmp(exec_name, UNLOCK_EXEC, sizeof(UNLOCK_EXEC) - 1) == 0) {
    return main_unlock(argc, argv);
  }
  fprintf(stderr, "Unknown executable %s for multicall binary\n", argv[0]);
  return 1;
}
