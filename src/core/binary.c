#include <stdlib.h>
#include <sys/mman.h>

#include "core/binary.h"
#include "core/error.h"
#include "core/mem.h"

BinaryFile *init_binary() {
  BinaryFile *binary = calloc(1, sizeof(BinaryFile));
  if (binary == NULL) {
    log_error("Failed to allocate memory for BinaryFile structure");
    return NULL;
  }

  binary->arena = arena_init();
  if (binary == NULL) {
    log_error("Failed to initialize memory arena");
    free(binary);
    return NULL;
  }

  binary->data = NULL;
  binary->parsed = NULL;
  binary->handler = NULL;

  return binary;
}

void free_binary(BinaryFile *bin) {
  if (bin == NULL)
    return;

  if (bin->data != NULL && bin->size > 0)
    ASSERT(bin->arena, munmap(bin->data, bin->size) == 0,
           ERR_FILE_UNMMAP_FAILED, "Failed to unmap memory");

  arena_destroy(bin->arena);
  free(bin);
}
