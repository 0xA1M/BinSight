#ifndef FORMAT_H
#define FORMAT_H

#include "error.h"

#define X_EXEC CONST_STR("application/x-executable")
#define X_PIE_EXEC CONST_STR("application/x-pie-executable")
#define X_SHAREDLIB CONST_STR("application/x-sharedlib")
#define X_MACH_BIN CONST_STR("application/x-mach-binary")
#define X_DOSEXEC CONST_STR("application/x-dosexec")
#define X_PORTEXEC CONST_STR("application/vnd.microsoft.portable-executable")

typedef struct FormatHandler {
  String name;
  BinaryFormat format;

  // Loader function
  BError (*load)(Binary *bin);

  // Print function
  void (*print)(Arena *arena, ELFInfo *parsed_data);
} FormatHandler;

Binary *load_binary(String path);

#endif // FORMAT_H
