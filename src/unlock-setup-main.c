// split out main() for multi-call static binary

extern int main_setup(int argc, char *argv[]);

int main(int argc, char *argv[]) {
  return main_setup(argc, argv);
}
