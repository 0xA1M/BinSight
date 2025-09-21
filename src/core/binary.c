#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "core/binary.h"
#include "core/error.h"

Binary *init_binary() {
  Binary *binary = calloc(1, sizeof(Binary));
  if (binary == NULL) {
    LOG_ERR("Failed to allocate memory for BinaryFile structure");
    return NULL;
  }

  binary->arena = arena_init();
  if (binary->arena == NULL) {
    LOG_ERR("Failed to initialize memory arena");
    free(binary);
    return NULL;
  }

  binary->data = NULL;
  binary->handler = NULL;
  memset(&binary->parsed, 0, sizeof(binary->parsed));

  return binary;
}

void free_binary(Binary *bin) {
  if (bin == NULL)
    return;

  if (bin->data != NULL && bin->size > 0)
    ASSERT(bin->arena, munmap(bin->data, bin->size) == 0,
           ERR_FILE_UNMMAP_FAILED, "Failed to unmap memory");

  arena_destroy(bin->arena);
  free(bin);
}
