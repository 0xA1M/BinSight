#include <fcntl.h>
#include <magic.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/error.h"
#include "core/format.h"
#include "formats/elf/elf_loader.h"
#include "formats/elf/elf_print.h"

// TODO: use a hash map for handlers so plugins can register themselves with
static const FormatHandler handlers[] = {
    {.name = "ELF", .format = FORMAT_ELF, .load = load_elf, .print = print_elf},
};

// TODO: Allow user to specify path to the magic db or use the default one on
// the system <- robustly locate it (somehow)
static BinaryFormat detect_format(const int fd) {
  BinaryFormat fmt = FORMAT_UNKNOWN;

  magic_t cookie = magic_open(MAGIC_MIME_TYPE | MAGIC_ERROR);
  ASSERT_RET_VAL(cookie != NULL, FORMAT_UNKNOWN, ERR_FORMAT_MAGIC_INIT_FAILED,
                 "Failed to initialize libmagic");

  ASSERT_GOTO(magic_load(cookie, NULL) == 0, cleanup,
              ERR_FORMAT_MAGIC_LOAD_FAILED,
              "Failed to load libmagic database: %s", magic_errno(cookie));

  const char *result = magic_descriptor(cookie, fd);
  ASSERT_GOTO(result != NULL, cleanup, ERR_FORMAT_MAGIC_DETECT_FAILED,
              "Failed to detect file format: %s", magic_error(cookie));

  fmt = get_binary_format(result);
  if (fmt == FORMAT_UNKNOWN)
    fprintf(stderr, "Unsupported file type: %s", result);

cleanup:
  magic_close(cookie);
  return fmt;
}

BinaryFile *load_binary(const char *path) {
  int fd = -1;
  BinaryFormat fmt = FORMAT_UNKNOWN;
  const FormatHandler *handler = NULL;
  struct stat sb = {0};
  uint64_t f_size = 0;
  uint8_t *mapped_mem = NULL;
  BinaryFile *binary = NULL;
  BError err = BERR_OK;

  fd = open(path, O_RDONLY);
  ASSERT_GOTO_ERRNO(fd != -1, cleanup_fd, ERR_FILE_OPEN_FAILED,
                    "Failed to open file '%s'", path);

  fmt = detect_format(fd);
  ASSERT_GOTO(fmt != FORMAT_UNKNOWN, cleanup_fd, ERR_FORMAT_UNKNOWN,
              "Could not detect binary format for '%%s'", path);

  for (size_t i = 0; i < ARR_COUNT(handlers); i++) {
    if (handlers[i].format == fmt) {
      handler = &handlers[i];
      break;
    }
  }
  ASSERT_GOTO(handler != NULL, cleanup_fd, ERR_FORMAT_HANDLER_NOT_FOUND,
              "No handler found for '%s'. Format not supported",
              lookup_binary_format(fmt));

  ASSERT_GOTO_ERRNO(fstat(fd, &sb) != -1, cleanup_fd, ERR_FILE_STAT_FAILED,
                    "Failed to get file metadata for '%s'", path);

  f_size = sb.st_size;
  ASSERT_GOTO(f_size > 0, cleanup_fd, ERR_FILE_READ_FAILED,
              "File '%s' is empty", path);

  ASSERT_GOTO(!S_ISDIR(sb.st_mode), cleanup_fd, ERR_FILE_IS_DIRECTORY,
              "Path '%s' is a directory", path);

  mapped_mem = mmap(NULL, f_size, PROT_READ, MAP_PRIVATE, fd, 0);
  ASSERT_GOTO_ERRNO(mapped_mem != MAP_FAILED, cleanup_fd, ERR_FILE_MMAP_FAILED,
                    "Failed to map file '%s' into memory", path);

  // File descriptor no longer needed
  int close_res = close(fd);
  if (close_res == -1) {
    err = berr_from_errno(ERR_IO_UNKNOWN, "Failed to close file descriptor",
                          __FILE__, __LINE__, __func__);
    berr_print(&err);
  }
  fd = -1;

  binary = init_binary();
  ASSERT_GOTO(binary != NULL, cleanup_mmap, ERR_MEM_ALLOC_FAILED,
              "Failed to initialize BinaryFile structure");

  binary->format = fmt;
  binary->handler = handler;
  binary->size = f_size;
  binary->data = mapped_mem;

  binary->arena = arena_init();
  ASSERT_GOTO(binary->arena != NULL, cleanup_binary, ERR_MEM_ALLOC_FAILED,
              "Failed to initialize memory arena for binary");

  binary->path = arena_strdup(binary->arena, path, strlen(path));
  ASSERT_GOTO(binary->path != NULL, cleanup_binary, ERR_MEM_ALLOC_FAILED,
              "Failed to duplicate binary path string");

  err = handler->load(binary);
  ASSERT_GOTO(IS_OK(err), cleanup_binary, ERR_FORMAT_PARSE_FAILED,
              "Failed to parse binary for format '%s'",
              lookup_binary_format(fmt));

  return binary;

cleanup_binary:
  free_binary(binary);
  mapped_mem = NULL;
cleanup_mmap:
  if (mapped_mem != NULL) {
    int munmap_res = munmap(mapped_mem, f_size);
    if (munmap_res == -1) {
      BError munmap_err =
          berr_from_errno(ERR_FILE_MMAP_FAILED, "Failed to unmap memory",
                          __FILE__, __LINE__, __func__);
      berr_print(&munmap_err);
    }
  }
cleanup_fd:
  if (fd != -1) {
    int close_result = close(fd);
    if (close_result == -1) {
      BError close_err =
          berr_from_errno(ERR_IO_UNKNOWN, "Failed to close file descriptor",
                          __FILE__, __LINE__, __func__);
      berr_print(&close_err);
    }
  }
  return NULL;
}
