#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "core/binary.h"
#include "core/format.h"

BinaryFile *init_binary(const char *path, const BinaryFormat fmt,
                        uint64_t f_size) {
  BinaryFile *binary = calloc(1, sizeof(BinaryFile));
  if (binary == NULL)
    return NULL;

  binary->path = strdup(path);
  binary->format = fmt;

  binary->data = NULL;
  binary->size = f_size;

  binary->arch = NULL;
  binary->build_id = NULL;
  binary->parsed = NULL;

  return binary;
}

void free_binary(BinaryFile *bin) {
  free(bin->path);
  free(bin->arch);
  free(bin->build_id);

  if (bin->handler && bin->handler->free && bin->parsed)
    bin->handler->free(bin->parsed);

  if (bin->data)
    munmap(bin->data, bin->size);

  free(bin);
}
