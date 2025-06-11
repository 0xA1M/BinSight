#include <errno.h>
#include <magic.h>
#include <stdlib.h>
#include <string.h>

#include "binary.h"
#include "formats/elf/elf_loader.h"
#include "utils.h"

static BinaryFormat detect_format(const char *path) {
  magic_t cookie = magic_open(MAGIC_MIME_TYPE | MAGIC_ERROR);
  if (cookie == NULL) {
    fprintf(stderr, "Failed to initialize libmagic\n");
    return FORMAT_UNKNOWN;
  }

  if (magic_load(cookie, NULL) != 0) {
    fprintf(stderr, "Failed to load magic database: %s\n", magic_error(cookie));
    magic_close(cookie);
    return FORMAT_UNKNOWN;
  }

  const char *result = magic_file(cookie, path);
  if (result == NULL) {
    fprintf(stderr, "File format detection failed: %s\n", magic_error(cookie));
    magic_close(cookie);
    return FORMAT_UNKNOWN;
  }

  bool valid = false;
  const char *exe_types[] = {
      "application/x-executable",                     // Linux
      "application/x-pie-executable",                 // Linux
      "application/x-sharedlib",                      // Linux
      "application/x-mach-binary",                    // macOS
      "application/x-dosexec",                        // Windows
      "application/vnd.microsoft.portable-executable" // Windows};
  };

  for (size_t i = 0; i < ARR_COUNT(exe_types); i++) {
    if (strncmp(result, exe_types[i], strlen(exe_types[i])) == 0) {
      valid = true;
      break;
    }
  }

  if (valid == false) {
    const char *dir = "inode/directory";

    if (strncmp(result, dir, strlen(dir)) == 0)
      fprintf(stderr, "Path is a directory: %s\n", path);
    else
      fprintf(stderr, "Unsupported file type: %s\n", result);

    magic_close(cookie);
    return FORMAT_UNKNOWN;
  }

  BinaryFormat fmt = get_binary_format(result);

  magic_close(cookie);
  return fmt;
}

BinaryFile *load_binary(const char *path) {
  if (!is_file_exist(path)) {
    fprintf(stderr, "File does not exist or cannot be accessed: %s\n", path);
    return NULL;
  }

  BinaryFormat fmt = detect_format(path);
  if (fmt == FORMAT_UNKNOWN)
    return NULL;

  FILE *f = fopen(path, "rw");
  if (f == NULL) {
    fprintf(stderr, "Failed to open file: %s\n", strerror(errno));
    return NULL;
  }

  long f_size = get_file_size(f);
  if (f_size == -1) {
    fclose(f);
    return NULL;
  }

  BinaryFile *binary = init_binary(path, fmt, f_size);
  if (binary == NULL) {
    fclose(f);
    return NULL;
  }

  switch (fmt) {
  case FORMAT_ELF:
    if (load_elf(f, binary) == -1) {
      fclose(f);
      free(binary);
      return NULL;
    }
    break;
  default:
    not_implemented();
    break;
  }

  fclose(f);
  return binary;
}
