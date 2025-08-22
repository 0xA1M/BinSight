#include "formats/elf/elf_loader.h"
#include "formats/elf/elf_parser.h"

BError load_elf(BinaryFile *bin) {
  CHECK(bin != NULL, ERR_ARG_NULL, "BinaryFile pointer is NULL");

  ELFInfo *elf = init_elf(bin->arena);
  CHECK(elf != NULL, ERR_MEM_ALLOC_FAILED,
        "Failed to allocate memory for ELFInfo");

  CHECK(EI_CLASS < bin->size, ERR_FORMAT_HEADER_TOO_SMALL,
        "ELF identification class byte is out of bounds");
  CHECK(EI_DATA < bin->size, ERR_FORMAT_HEADER_TOO_SMALL,
        "ELF identification data byte is out of bounds");

  bin->bitness = bin->data[EI_CLASS] == ELFCLASS32   ? BITNESS_32
                 : bin->data[EI_CLASS] == ELFCLASS64 ? BITNESS_64
                                                     : BITNESS_UNKNOWN;

  bin->endianness = bin->data[EI_DATA] == ELFDATA2LSB   ? ENDIANNESS_LITTLE
                    : bin->data[EI_DATA] == ELFDATA2MSB ? ENDIANNESS_BIG
                                                        : ENDIANNESS_UNKNOWN;

  RET_IF_ERR(parse_elf(bin, elf));

  bin->parsed = (void *)elf;

  return BERR_OK;
}
