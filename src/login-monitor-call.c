// split out main() for multi-call static binary

extern int main_monitor(int argc, char *argv[]);

int main(int argc, char *argv[]) {
  return main_monitor(argc, argv);
}
