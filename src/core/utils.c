#include "core/utils.h"
#include "core/format.h"

BinaryFormat get_binary_format(Arena *arena, String mime) {
  ASSERT_RET_VAL(arena, mime.str != NULL, FORMAT_UNKNOWN, ERR_FORMAT_UNKNOWN,
                 "Unknown binary file format");

  if (string_eq(mime, X_EXEC) || string_eq(mime, X_PIE_EXEC) ||
      string_eq(mime, X_SHAREDLIB))
    return FORMAT_ELF;

  if (string_eq(mime, X_MACH_BIN))
    return FORMAT_MACHO;

  if (string_eq(mime, X_DOSEXEC) || string_eq(mime, X_PORTEXEC))
    return FORMAT_PE;

  return FORMAT_UNKNOWN;
}

String lookup_binary_format(BinaryFormat fmt) {
  switch (fmt) {
  case FORMAT_ELF:
    return CONST_STR("ELF");
  case FORMAT_PE:
    return CONST_STR("PE");
  case FORMAT_MACHO:
    return CONST_STR("MACHO");
  case FORMAT_UNKNOWN:
  default:
    return CONST_STR("unknown");
  }
}
