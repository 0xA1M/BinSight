#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/mem.h"
#include "formats/elf/elf_utils.h"

/* Init & cleanup */
ELFInfo *init_elf(Arena *arena) {
  ELFInfo *elf = arena_alloc(arena, sizeof(ELFInfo));
  if (elf == NULL) {
    fprintf(stderr, "Failed to allocate memory for ELFInfo from arena\n");
    return NULL;
  }

  return elf;
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
