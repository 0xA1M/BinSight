#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_utils.h"

static Elf32_Ehdr *parse_elf32_hdr(const unsigned char *buffer) {
  Elf32_Ehdr *header = calloc(1, sizeof(Elf32_Ehdr));
  if (header == NULL) {
    fprintf(stderr, "Failed to allocate memory to store ELF header: %s\n",
            strerror(errno));
    return NULL;
  }

  memcpy(header->e_ident, buffer, EI_NIDENT);
  int is_little_endian = (header->e_ident[EI_DATA] == ELFDATA2LSB);

  size_t offset = EI_NIDENT;
  header->e_type = read_elf_half(buffer, offset, is_little_endian);
  offset += 2;
  header->e_machine = read_elf_half(buffer, offset, is_little_endian);
  offset += 2;
  header->e_version = read_elf_word(buffer, offset, is_little_endian);
  offset += 4;
  header->e_entry = read_elf_word(buffer, offset, is_little_endian); // 32-bit
  offset += 4;
  header->e_phoff = read_elf_word(buffer, offset, is_little_endian); // 32-bit
  offset += 4;
  header->e_shoff = read_elf_word(buffer, offset, is_little_endian); // 32-bit
  offset += 4;
  header->e_flags = read_elf_word(buffer, offset, is_little_endian);
  offset += 4;
  header->e_ehsize = read_elf_half(buffer, offset, is_little_endian);
  offset += 2;
  header->e_phentsize = read_elf_half(buffer, offset, is_little_endian);
  offset += 2;
  header->e_phnum = read_elf_half(buffer, offset, is_little_endian);
  offset += 2;
  header->e_shentsize = read_elf_half(buffer, offset, is_little_endian);
  offset += 2;
  header->e_shnum = read_elf_half(buffer, offset, is_little_endian);
  offset += 2;
  header->e_shstrndx = read_elf_half(buffer, offset, is_little_endian);

  return header;
}

static Elf64_Ehdr *parse_elf64_hdr(const unsigned char *buffer) {
  Elf64_Ehdr *header = calloc(1, sizeof(Elf64_Ehdr));
  if (header == NULL) {
    fprintf(stderr, "Failed to allocate memory to store ELF header: %s\n",
            strerror(errno));
    return NULL;
  }

  memcpy(header->e_ident, buffer, EI_NIDENT);

  bool is_little_endian = (header->e_ident[EI_DATA] == ELFDATA2LSB);

  size_t offset = EI_NIDENT;
  header->e_type = read_elf_half(buffer, offset, is_little_endian);

  offset += 2;
  header->e_machine = read_elf_half(buffer, offset, is_little_endian);

  offset += 2;
  header->e_version = read_elf_word(buffer, offset, is_little_endian);

  offset += 4;
  header->e_entry = read_elf_xword(buffer, offset, is_little_endian);

  offset += 8;
  header->e_phoff = read_elf_xword(buffer, offset, is_little_endian);

  offset += 8;
  header->e_shoff = read_elf_xword(buffer, offset, is_little_endian);

  offset += 8;
  header->e_flags = read_elf_word(buffer, offset, is_little_endian);

  offset += 4;
  header->e_ehsize = read_elf_half(buffer, offset, is_little_endian);

  offset += 2;
  header->e_phentsize = read_elf_half(buffer, offset, is_little_endian);

  offset += 2;
  header->e_phnum = read_elf_half(buffer, offset, is_little_endian);

  offset += 2;
  header->e_shentsize = read_elf_half(buffer, offset, is_little_endian);

  offset += 2;
  header->e_shnum = read_elf_half(buffer, offset, is_little_endian);

  offset += 2;
  header->e_shstrndx = read_elf_half(buffer, offset, is_little_endian);

  return header;
}

int parse_elf32(const unsigned char *buffer, ELFInfo *elf) {
  Elf32_Ehdr *header = parse_elf32_hdr(buffer);
  if (header == NULL)
    return -1;

  print_elf_header(header);

  elf->ehdr = header;

  return 0;
}

int parse_elf64(const unsigned char *buffer, ELFInfo *elf) {
  Elf64_Ehdr *header = parse_elf64_hdr(buffer);
  if (header == NULL)
    return -1;

  print_elf_header(header);

  elf->ehdr = (void *)header;

  return 0;
}
