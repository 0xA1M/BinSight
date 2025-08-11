#include <errno.h>
#include <fcntl.h>
#include <magic.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/binary.h"
#include "core/format.h"
#include "core/mem.h"
#include "core/utils.h"
#include "formats/elf/elf_loader.h"
#include "formats/elf/elf_print.h"

static const FormatHandler handlers[] = {
    {.name = "ELF", .format = FORMAT_ELF, .load = load_elf, .print = print_elf},
};

static BinaryFormat detect_format(const int fd) {
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

  const char *result = magic_descriptor(cookie, fd);
  if (result == NULL) {
    fprintf(stderr, "File format detection failed: %s\n", magic_error(cookie));
    magic_close(cookie);
    return FORMAT_UNKNOWN;
  }

  BinaryFormat fmt = get_binary_format(result);
  if (fmt == FORMAT_UNKNOWN)
    fprintf(stderr, "Unsupported file type: %s\n", result);

  magic_close(cookie);
  return fmt;
}

BinaryFile *load_binary(const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "Failed to open file: %s\n", strerror(errno));
    return NULL;
  }

  BinaryFormat fmt = detect_format(fd);
  if (fmt == FORMAT_UNKNOWN)
    return NULL;

  const FormatHandler *handler = NULL;
  for (size_t i = 0; i < ARR_COUNT(handlers); i++) {
    if (handlers[i].format == fmt) {
      handler = &handlers[i];
      break;
    }
  }

  if (handler == NULL) {
    fprintf(stderr, "No handler found for format. %s format not supported!\n",
            print_binary_format(fmt));
    return NULL;
  }

  struct stat sb = {0};
  if (fstat(fd, &sb) == -1) {
    fprintf(stderr, "Failed to get file size: %s\n", strerror(errno));
    close(fd);
    return NULL;
  }

  uint64_t f_size = sb.st_size;

  if (S_ISDIR(sb.st_mode)) {
    fprintf(stderr, "Path is a directory: %s\n", path);
    close(fd);
    return NULL;
  }

  uint8_t *mapped_mem = mmap(NULL, f_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);

  if (mapped_mem == MAP_FAILED) {
    fprintf(stderr, "Failed to map file into memory: %s\n", strerror(errno));
    return NULL;
  }

  BinaryFile *binary = init_binary(path, fmt, f_size);
  if (binary == NULL) {
    munmap(mapped_mem, f_size);
    return NULL;
  }

  binary->arena = arena_init();
  if (binary->arena == NULL) {
    free_binary(binary);
    return NULL;
  }

  binary->handler = handler;
  binary->data = mapped_mem;

  if (handler->load(binary) == -1) {
    free_binary(binary);
    return NULL;
  }

  return binary;
}
