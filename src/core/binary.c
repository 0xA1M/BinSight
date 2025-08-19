#include <stdlib.h>
#include <sys/mman.h>

#include "core/binary.h"
#include "core/mem.h"

BinaryFile *init_binary() {
  BinaryFile *binary = calloc(1, sizeof(BinaryFile));
  if (binary == NULL)
    return NULL;

  return binary;
}

void free_binary(BinaryFile *bin) {
  if (bin->data)
    munmap(bin->data, bin->size);

  arena_destroy(bin->arena);
  free(bin);
}
