#include <elf.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "elf_loader.h"
#include "elf_parser.h"

int load_elf(FILE *f, BinaryFile *bin) {
  bin->data = calloc(bin->size, sizeof(unsigned char));
  if (bin->data == NULL) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    return -1;
  }

  size_t bytes_read = fread(bin->data, 1, bin->size, f);
  if (bytes_read != bin->size) {
    fprintf(stderr, "Failed to read the binary: %s\n", strerror(errno));
    free(bin->data);
    return -1;
  }

  ELFInfo *elf = init_elf();
  if (elf == NULL) {
    free(bin->data);
    return -1;
  }

  bin->bitness = bin->data[EI_CLASS] == 1   ? BITNESS_32
                 : bin->data[EI_CLASS] == 2 ? BITNESS_64
                                            : BITNESS_UNKNOWN;

  bin->endianness = bin->data[EI_DATA] == 1   ? ENDIANNESS_LITTLE
                    : bin->data[EI_DATA] == 2 ? ENDIANNESS_BIG
                                              : ENDIANNESS_UNKNOWN;

  switch (bin->bitness) {
  case BITNESS_32:
    if (parse_elf32(bin->data, elf) == -1) {
      free(elf);
      free(bin->data);
      return -1;
    }
    break;
  case BITNESS_64:
    if (parse_elf64(bin->data, elf)) {
      free(elf);
      free(bin->data);
      return -1;
    }
    break;
  default:
    fprintf(stderr, "Failed to parse ELF: unknown bitness!\n");
    break;
  }

  bin->parsed = elf;

  return 0;
}
