// split out main() for multi-call static binary

extern int main_unlock(int argc, char *argv[]);

int main(int argc, char *argv[]) {
  return main_unlock(argc, argv);
}
