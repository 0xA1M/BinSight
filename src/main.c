#include <stdio.h>

#include "core/binary.h"
#include "core/format.h"

int main(int argc, const char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
    return -1;
  }

  BinaryFile *binary = load_binary(argv[1]);
  if (binary == NULL)
    return -1;

  free_binary(binary);

  return 0;
}
