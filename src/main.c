#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/format.h"

// TODO: Better Logging
// TODO: Better command line argument using getopt and create the headless CLI
// mode
int main(int argc, const char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
    return EXIT_FAILURE;
  }

  String path = {.str = argv[1], .len = strlen(argv[1])};
  Binary *binary = load_binary(path);
  if (binary == NULL)
    goto cleanup;

  // The printing function will turn into an ELF module
  if (binary->handler && binary->handler->print)
    binary->handler->print(binary->arena, binary->parsed.elf);

cleanup:
  free_binary(binary);
  return EXIT_SUCCESS;
}
