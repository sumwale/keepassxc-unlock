// entry point for multi-call static binary

#include <stdio.h>
#include <string.h>

extern int main_monitor(int argc, char *argv[]);
extern int main_setup(int argc, char *argv[]);
extern int main_unlock(int argc, char *argv[]);

#ifndef PRODUCT_ID
  #define PRODUCT_ID 1
#endif
#if PRODUCT_ID == 1
  #define PRODUCT_LCASE "keepassxc"
#else
  #define PRODUCT_LCASE "chipass"
#endif
#define MONITOR_EXEC PRODUCT_LCASE "-login-monitor"
#define SETUP_EXEC PRODUCT_LCASE "-unlock-setup"
#define UNLOCK_EXEC PRODUCT_LCASE "-unlock"
#define ALL_EXEC PRODUCT_LCASE "-unlock-all"


int main(int argc, char *argv[]) {
  const char *exec_name = strrchr(argv[0], '/');
  if (exec_name) {
    exec_name++;
  } else {
    exec_name = argv[0];
  }
  if (strncmp(exec_name, ALL_EXEC, sizeof(ALL_EXEC) - 1) == 0) {
    fprintf(stderr, "Cannot directly invoke multi-call binary\n");
    return 1;
  } else if (strncmp(exec_name, MONITOR_EXEC, sizeof(MONITOR_EXEC) - 1) == 0) {
    return main_monitor(argc, argv);
  } else if (strncmp(exec_name, SETUP_EXEC, sizeof(SETUP_EXEC) - 1) == 0) {
    return main_setup(argc, argv);
  } else if (strncmp(exec_name, UNLOCK_EXEC, sizeof(UNLOCK_EXEC) - 1) == 0) {
    return main_unlock(argc, argv);
  }
  fprintf(stderr, "Unknown executable %s for multi-call binary\n", argv[0]);
  return 1;
}
