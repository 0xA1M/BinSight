#include <string.h>

#include "core/binary.h"
#include "core/format.h"
#include "core/utils.h"

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
  switch (fmt) {
  case FORMAT_ELF:
    return "ELF";
  case FORMAT_PE:
    return "PE";
  case FORMAT_MACHO:
    return "MACHO";
  case FORMAT_UNKNOWN:
  default:
    return "unknown";
  }
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

void print_hex(const unsigned char *buf, size_t len) {
  for (size_t i = 1; i <= len; i++) {
    printf("%02X ", buf[i - 1]);

    if (i % 32 == 0)
      printf("\n");
  }

  printf("\n");
}
