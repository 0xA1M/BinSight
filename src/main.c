#include <stdio.h>
#include <stdlib.h>

#include "core/format.h"

// TODO: Better Logging
// TODO: Better command line argument using getopt
int main(int argc, const char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
    return EXIT_FAILURE;
  }

  Arena *berr_arena = arena_init();
  if (berr_arena == NULL) {
    fprintf(stderr, "Fatal: Failed to initialize error handling arena.\n");
    return EXIT_FAILURE;
  }
  berr_set_arena(berr_arena);

  BinaryFile *binary = load_binary(argv[1]);
  if (binary == NULL) {
    arena_destroy(berr_arena);
    return EXIT_FAILURE;
  }

  if (binary->handler && binary->handler->print)
    binary->handler->print(binary->parsed);

  free_binary(binary);
  arena_destroy(berr_arena);
  return EXIT_SUCCESS;
}
