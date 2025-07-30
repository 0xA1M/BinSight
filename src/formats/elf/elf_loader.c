#include <elf.h>
#include <stdlib.h>

#include "formats/elf/elf_loader.h"
#include "formats/elf/elf_parser.h"

int load_elf(BinaryFile *bin) {
  ELFInfo *elf = init_elf();
  if (elf == NULL)
    return -1;

  bin->bitness = bin->data[EI_CLASS] == ELFCLASS32   ? BITNESS_32
                 : bin->data[EI_CLASS] == ELFCLASS64 ? BITNESS_64
                                                     : BITNESS_UNKNOWN;

  bin->endianness = bin->data[EI_DATA] == ELFDATA2LSB   ? ENDIANNESS_LITTLE
                    : bin->data[EI_DATA] == ELFDATA2MSB ? ENDIANNESS_BIG
                                                        : ENDIANNESS_UNKNOWN;

  if (parse_elf(bin, elf) == -1) {
    free(elf);
    return -1;
  }

  bin->parsed = (void *)elf;
  return 0;
}
