#include <string.h>

#include "core/binary.h"
#include "core/format.h"
#include "core/utils.h"

BinaryFormat get_binary_format(const char *mime_str) {
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

const char *print_binary_format(BinaryFormat fmt) {
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
