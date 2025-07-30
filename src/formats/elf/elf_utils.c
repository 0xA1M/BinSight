#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "formats/elf/elf_utils.h"

/* Init & cleanup */
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

void free_elf(void *elf_ptr) {
  ELFInfo *elf = (ELFInfo *)elf_ptr;

  if (!elf)
    return;

  // Free header and tables
  free(elf->ehdr);
  free(elf->phdrs);
  free(elf->shdrs);

  // Section name string table
  free(elf->shstrtab);

  // General string table
  free(elf->strtab);
  free(elf->dynstr);

  // Free symbol table
  if (elf->symtab) {
    free(elf->symtab);
    elf->symtab = NULL;
  }

  if (elf->dynsym) {
    free(elf->dynsym);
    elf->dynsym = NULL;
  }

  // Free relocation entries
  if (elf->rela) {
    free(elf->rela);
    elf->rela = NULL;
  }

  free(elf);
}

/* Section headers utility functions */
const char *get_section_name(const ELFInfo *elf, size_t section_index) {
  if (!elf || !elf->shstrtab || !elf->shdrs ||
      section_index >= ((Elf64_Ehdr *)elf->ehdr)->e_shnum) {
    return NULL;
  }

  uint32_t name_offset = elf->shdrs[section_index].sh_name;
  return elf->shstrtab + name_offset;
}

int find_section_by_name(const ELFInfo *elf, const char *name) {
  if (!elf || !name) {
    return -1;
  }

  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf->ehdr;
  for (size_t i = 0; i < ehdr->e_shnum; i++) {
    const char *section_name = get_section_name(elf, i);
    if (section_name && strcmp(section_name, name) == 0) {
      return (int)i;
    }
  }

  return -1;
}
