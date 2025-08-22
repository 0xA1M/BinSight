#include <stdlib.h>
#include <sys/mman.h>

#include "core/binary.h"
#include "core/error.h"
#include "core/mem.h"

BinaryFile *init_binary() {
  BinaryFile *binary = calloc(1, sizeof(BinaryFile));
  ASSERT_RET_VAL_ERRNO(binary != NULL, NULL, ERR_MEM_ALLOC_FAILED,
                       "Failed to allocate memory for BinaryFile");

  return binary;
}

void free_binary(BinaryFile *bin) {
  if (bin == NULL)
    return;

  if (bin->data != NULL) {
    int munmap_res = munmap(bin->data, bin->size);
    if (munmap_res != 0) {
      BError err =
          berr_from_errno(ERR_FILE_UNMMAP_FAILED, "Failed to unmap memory",
                          __FILE__, __LINE__, __func__);
      berr_print(&err);
    }
  }

  arena_destroy(bin->arena);
  free(bin);
}
