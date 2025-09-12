#include <bits/posix1_lim.h>
#include <fcntl.h>
#include <magic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/format.h"
#include "core/mem.h"
#include "core/utils.h"

#include "formats/elf/elf_loader.h"
#include "formats/elf/elf_print.h"

// TODO: use a hash map for handlers for future expansions (maybe support
// images, audio...etc)
static const FormatHandler handlers[] = {
    {
        .name = {"ELF", 3},
        .format = FORMAT_ELF,
        .load = load_elf,
        .print = print_elf,
    },
};

static uint8_t *map_file(Arena *arena, const char *path, uint64_t *f_size) {
  uint8_t *mapped = NULL;

  struct stat sb = {0};
  ASSERT_RET_VAL_ERRNO(arena, lstat(path, &sb) != -1, NULL,
                       ERR_FILE_STAT_FAILED, "Failed to stat path '%s'", path);
  ASSERT_RET_VAL(arena, !S_ISLNK(sb.st_mode), NULL, ERR_FILE_IS_SYM_LINK,
                 "Refusing to open symlink: %s", path);

  int fd = open(path, O_RDONLY);
  ASSERT_RET_VAL(arena, fd != -1, NULL, ERR_FILE_OPEN_FAILED,
                 "Failed to open file '%s'", path);

  ASSERT_GOTO_ERRNO(arena, fstat(fd, &sb) != -1, cleanup, ERR_FILE_STAT_FAILED,
                    "Failed to get file metadata for '%s'", path);

  ASSERT_GOTO(arena, !S_ISDIR(sb.st_mode), cleanup, ERR_FILE_IS_DIRECTORY,
              "Path '%s' is a directory", path);
  ASSERT_GOTO(arena, sb.st_size >= 0, cleanup, ERR_FILE_READ_FAILED,
              "File '%s' has invalid size", path);
  ASSERT_GOTO(arena, (size_t)sb.st_size <= SIZE_MAX, cleanup,
              ERR_FILE_READ_FAILED, "File '%s' is too large to map safely",
              path);

  *f_size = (uint64_t)sb.st_size;

  mapped = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  ASSERT_GOTO_ERRNO(arena, mapped != MAP_FAILED, cleanup, ERR_FILE_MMAP_FAILED,
                    "Failed to map file '%s' into memory", path);

cleanup:
  ASSERT(arena, close(fd) != -1, ERR_IO_UNKNOWN,
         "Failed to close file descriptor");
  return mapped;
}

// TODO: Allow user to specify path to the magic db or use the default one on
// the system <- robustly locate it (somehow)
static BinaryFormat detect_format(Arena *arena, const uint8_t *data,
                                  size_t size) {
  BinaryFormat fmt = FORMAT_UNKNOWN;

  magic_t cookie = magic_open(MAGIC_MIME_TYPE | MAGIC_ERROR);
  ASSERT_RET_VAL(arena, cookie != NULL, FORMAT_UNKNOWN,
                 ERR_FORMAT_MAGIC_INIT_FAILED, "Failed to initialize libmagic");

  ASSERT_GOTO(arena, magic_load(cookie, NULL) == 0, cleanup,
              ERR_FORMAT_MAGIC_LOAD_FAILED,
              "Failed to load libmagic database: %s", magic_errno(cookie));

  // Cap sample size; libmagic typically needs only a small prefix.
  const size_t SAMPLE_MAX = 4096;
  const size_t sample_size = size < SAMPLE_MAX ? size : SAMPLE_MAX;

  const char *result_str = magic_buffer(cookie, data, sample_size);
  ASSERT_GOTO(arena, result_str != NULL, cleanup,
              ERR_FORMAT_MAGIC_DETECT_FAILED,
              "Failed to detect file format: %s", magic_error(cookie));

  String result = {.str = result_str, .len = strlen(result_str)};
  fmt = get_binary_format(arena, result);
  if (fmt == FORMAT_UNKNOWN)
    fprintf(stderr, "Unsupported file type: " STR, (int)result.len, result.str);

cleanup:
  magic_close(cookie);
  return fmt;
}

static const FormatHandler *find_handler(BinaryFormat fmt) {
  for (size_t i = 0; i < ARR_COUNT(handlers); i++)
    if (handlers[i].format == fmt)
      return &handlers[i];

  return NULL;
}

Binary *load_binary(String path) {
  Binary *binary = NULL;

  binary = init_binary();
  if (binary == NULL)
    return NULL;

  binary->data = map_file(binary->arena, path.str, &binary->size);
  if (binary->data == NULL)
    return NULL;

  binary->format = detect_format(binary->arena, binary->data, binary->size);
  ASSERT_GOTO(binary->arena, binary->format != FORMAT_UNKNOWN, cleanup,
              ERR_FORMAT_UNKNOWN, "Could not detect binary format for " STR,
              (int)path.len, path.str);

  binary->handler = find_handler(binary->format);
  ASSERT_GOTO(binary->arena, binary->handler != NULL, cleanup,
              ERR_FORMAT_HANDLER_NOT_FOUND,
              "No handler found for %s. Format not supported",
              lookup_binary_format(binary->format).str);

  binary->path = string_new(binary->arena, path.str, path.len);
  ASSERT_GOTO(binary->arena, binary->path.str != NULL, cleanup,
              ERR_MEM_ALLOC_FAILED, "Failed to duplicate binary path string");

  BError err = binary->handler->load(binary);
  ASSERT_GOTO(binary->arena, IS_OK(err), cleanup, ERR_FORMAT_PARSE_FAILED,
              "Failed to parse binary for format %s",
              lookup_binary_format(binary->format).str);

  return binary;

cleanup:
  free_binary(binary);
  return NULL;
}
