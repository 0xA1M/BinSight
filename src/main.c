#include <stdio.h>

#include "core/binary.h"
#include "core/format.h"
#include "formats/elf/elf_utils.h"

// TODO: Better command line argument using getopt
int main(int argc, const char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
    return -1;
  }

  BinaryFile *binary = load_binary(argv[1]);
  if (binary == NULL)
    return -1;

  if (binary->handler && binary->handler->print)
    binary->handler->print((ELFInfo *)binary->parsed);

  free_binary(binary);
  return 0;
}
