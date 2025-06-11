#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_utils.h"

ELFInfo *init_elf(void) {
  ELFInfo *elf = calloc(1, sizeof(ELFInfo));
  if (elf == NULL) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    return NULL;
  }

  elf->ehdr = NULL;
  elf->phdrs = NULL;
  elf->shdrs = NULL;
  elf->shstrtab = NULL;
  elf->strtab = NULL;
  elf->symtab = NULL;
  elf->rela = NULL;

  return elf;
}

void free_elf(ELFInfo *elf) {
  free(elf->ehdr);
  free(elf->phdrs);
  free(elf->shdrs);
  free(elf->shstrtab);
  free(elf->strtab);
  free(elf->symtab);
  free(elf->rela);
  free(elf);

  elf = NULL;
}

uint16_t read_elf_half(const unsigned char *buf, size_t offset,
                       bool is_little_endian) {
  const unsigned char *p = buf + offset;

  if (is_little_endian)
    return p[0] | (p[1] << 8);

  return (p[0] << 8) | p[1];
}

uint32_t read_elf_word(const unsigned char *buf, size_t offset,
                       bool is_little_endian) {
  const unsigned char *p = buf + offset;

  if (is_little_endian)
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);

  return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

uint64_t read_elf_xword(const unsigned char *buf, size_t offset,
                        bool is_little_endian) {
  const unsigned char *p = buf + offset;

  if (is_little_endian)
    return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);

  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
         ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
         ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
         ((uint64_t)p[6] << 8) | ((uint64_t)p[7]);
}

static void print_e_ident(unsigned char *e_ident) {
  printf("ELF Header:\n");
  printf("  Magic:   ");
  for (int i = 0; i < EI_NIDENT; i++) {
    printf("%02x ", e_ident[i]);
  }
  printf("\n");
  printf("  Class:                             ");
  switch (e_ident[EI_CLASS]) {
  case ELFCLASS32:
    printf("ELF32\n");
    break;
  case ELFCLASS64:
    printf("ELF64\n");
    break;
  default:
    printf("Invalid\n");
    break;
  }
  printf("  Data:                              ");
  switch (e_ident[EI_DATA]) {
  case ELFDATA2LSB:
    printf("2's complement, little endian\n");
    break;
  case ELFDATA2MSB:
    printf("2's complement, big endian\n");
    break;
  default:
    printf("Invalid\n");
    break;
  }
  printf("  Version:                           %d\n", e_ident[EI_VERSION]);
}

static void print_elf32_header(Elf32_Ehdr *ehdr) {
  print_e_ident(ehdr->e_ident);
  printf("  Type:                              %u\n", ehdr->e_type);
  printf("  Machine:                           %u\n", ehdr->e_machine);
  printf("  Version:                           0x%x\n", ehdr->e_version);
  printf("  Entry point address:               0x%x\n", ehdr->e_entry);
  printf("  Start of program headers:          %u (bytes into file)\n",
         ehdr->e_phoff);
  printf("  Start of section headers:          %u (bytes into file)\n",
         ehdr->e_shoff);
  printf("  Flags:                             0x%x\n", ehdr->e_flags);
  printf("  Size of this header:               %u (bytes)\n", ehdr->e_ehsize);
  printf("  Size of program headers:           %u (bytes)\n",
         ehdr->e_phentsize);
  printf("  Number of program headers:         %u\n", ehdr->e_phnum);
  printf("  Size of section headers:           %u (bytes)\n",
         ehdr->e_shentsize);
  printf("  Number of section headers:         %u\n", ehdr->e_shnum);
  printf("  Section header string table index: %u\n", ehdr->e_shstrndx);
}

static void print_elf64_header(Elf64_Ehdr *ehdr) {
  print_e_ident(ehdr->e_ident);
  printf("  Type:                              %u\n", ehdr->e_type);
  printf("  Machine:                           %u\n", ehdr->e_machine);
  printf("  Version:                           0x%x\n", ehdr->e_version);
  printf("  Entry point address:               0x%lx\n", ehdr->e_entry);
  printf("  Start of program headers:          %lu (bytes into file)\n",
         ehdr->e_phoff);
  printf("  Start of section headers:          %lu (bytes into file)\n",
         ehdr->e_shoff);
  printf("  Flags:                             0x%x\n", ehdr->e_flags);
  printf("  Size of this header:               %u (bytes)\n", ehdr->e_ehsize);
  printf("  Size of program headers:           %u (bytes)\n",
         ehdr->e_phentsize);
  printf("  Number of program headers:         %u\n", ehdr->e_phnum);
  printf("  Size of section headers:           %u (bytes)\n",
         ehdr->e_shentsize);
  printf("  Number of section headers:         %u\n", ehdr->e_shnum);
  printf("  Section header string table index: %u\n", ehdr->e_shstrndx);
}

void print_elf_header(void *header) {
  int bitness = ((unsigned char *)header)[EI_CLASS];
  if (bitness == ELFCLASS32) {
    print_elf32_header((Elf32_Ehdr *)header);
  } else if (bitness == ELFCLASS64) {
    print_elf64_header((Elf64_Ehdr *)header);
  } else {
    printf("Unknown ELF class: %d\n", bitness);
  }
}
