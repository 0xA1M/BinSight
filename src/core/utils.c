#include <errno.h>
#include <string.h>

#include "format.h"
#include "utils.h"

inline BinaryFormat get_binary_format(const char *mime_str) {
  if (!mime_str)
    return FORMAT_UNKNOWN;

  if (strncmp(mime_str, X_EXEC, CSTR_LEN(X_EXEC)) == 0 ||
      strncmp(mime_str, X_PIE_EXEC, CSTR_LEN(X_PIE_EXEC)) == 0 ||
      strncmp(mime_str, X_SHAREDLIB, CSTR_LEN(X_SHAREDLIB)) == 0)
    return FORMAT_ELF;

  if (strncmp(mime_str, X_MACH_BIN, CSTR_LEN(X_MACH_BIN)) == 0)
    return FORMAT_MACHO;

  if (strncmp(mime_str, X_DOSEXEC, CSTR_LEN(X_DOSEXEC)) == 0 ||
      strncmp(mime_str, X_PORTEXEC, CSTR_LEN(X_PORTEXEC)) == 0)
    return FORMAT_PE;

  return FORMAT_UNKNOWN;
}

inline const char *print_binary_format(BinaryFormat fmt) {
  return fmt == FORMAT_UNKNOWN ? "unknown"
         : fmt == FORMAT_ELF   ? "ELF"
         : fmt == FORMAT_MACHO ? "MACHO"
         : fmt == FORMAT_PE    ? "PE"
                               : "unknown";
}

long get_file_size(FILE *f) {
  if (fseek(f, 0, SEEK_END) == -1) {
    fprintf(stderr, "Failed to seek to file end: %s\n", strerror(errno));
    return -1;
  }

  long f_size = ftell(f);
  if (f_size == -1) {
    fprintf(stderr, "Failed to get file size: %s\n", strerror(errno));
    return -1;
  }

  if (fseek(f, 0, SEEK_SET) == -1) {
    fprintf(stderr, "Failed to rewind file pointer: %s\n", strerror(errno));
    return -1;
  }

  return f_size;
}

bool is_file_exist(const char *path) {
  if (!path || !*path)
    return false;

  struct stat path_stat = {0};
  if (stat_func(path, &path_stat) != 0)
    return false;

#if defined(_WIN32) || defined(_WIN64)
  return (path_stat.st_mode & _S_IFMT) == _S_IFREG;
#else
  return S_ISREG(path_stat.st_mode);
#endif
}
