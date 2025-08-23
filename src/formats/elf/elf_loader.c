#include "formats/elf/elf_loader.h"
#include "core/error.h"
#include "formats/elf/elf_parser.h"
#include <stdio.h>

BError load_elf(BinaryFile *bin) {
  CHECK(bin->arena, bin->size >= EI_NIDENT, ERR_FORMAT_HEADER_TOO_SMALL,
        "Buffer too small to contain ELF identification");

  ELFInfo *elf = init_elf(bin->arena);
  CHECK(bin->arena, elf != NULL, ERR_MEM_ALLOC_FAILED,
        "Failed to allocate memory for ELFInfo");

  CHECK(bin->arena, EI_CLASS < bin->size, ERR_FORMAT_HEADER_TOO_SMALL,
        "ELF identification class byte is out of bounds");
  CHECK(bin->arena, EI_DATA < bin->size, ERR_FORMAT_HEADER_TOO_SMALL,
        "ELF identification data byte is out of bounds");

  bin->bitness = bin->data[EI_CLASS] == ELFCLASS32   ? BITNESS_32
                 : bin->data[EI_CLASS] == ELFCLASS64 ? BITNESS_64
                                                     : BITNESS_UNKNOWN;

  bin->endianness = bin->data[EI_DATA] == ELFDATA2LSB   ? ENDIANNESS_LITTLE
                    : bin->data[EI_DATA] == ELFDATA2MSB ? ENDIANNESS_BIG
                                                        : ENDIANNESS_UNKNOWN;

  size_t expected_ehdr_size =
      (bin->bitness == BITNESS_32) ? sizeof(Elf32_Ehdr) : sizeof(Elf64_Ehdr);
  CHECK(bin->arena, bin->size >= expected_ehdr_size,
        ERR_FORMAT_HEADER_TOO_SMALL, "Buffer too small to contain ELF header");

  RET_IF_ERR(parse_elf(bin, elf));

  bin->is_pie = elf->ehdr->e_type == ET_DYN;
  bin->parsed = (void *)elf;

  return BERR_OK;
}
