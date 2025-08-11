#include <stdio.h>

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
