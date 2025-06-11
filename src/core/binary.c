#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "binary.h"
#include "formats/elf/elf_utils.h"
#include "utils.h"

BinaryFile *init_binary(const char *path, const BinaryFormat fmt, long f_size) {
  BinaryFile *binary = calloc(1, sizeof(BinaryFile));
  if (binary == NULL)
    return NULL;

  binary->path = strdup(path);
  binary->format = fmt;
  binary->size = f_size;

  binary->arch = NULL;
  binary->build_id = NULL;
  binary->data = NULL;
  binary->parsed = NULL;

  return binary;
}

void free_binary(BinaryFile *bin) {
  free(bin->path);
  free(bin->arch);
  free(bin->build_id);

  switch (bin->format) {
  case FORMAT_ELF:
    free_elf((ELFInfo *)bin->parsed);
    break;
  case FORMAT_PE:
    not_implemented();
    break;
  case FORMAT_MACHO:
    not_implemented();
  default:
    break;
  }

  free(bin->data);
  free(bin);

  bin = NULL;
}
