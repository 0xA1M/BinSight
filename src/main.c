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

  BinaryFile *binary = load_binary(argv[1]);
  if (binary == NULL)
    goto cleanup;

  if (binary->handler && binary->handler->print)
    binary->handler->print(binary->arena, binary->parsed);

cleanup:
  free_binary(binary);
  return EXIT_SUCCESS;
}
