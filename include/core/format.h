#ifndef FORMAT_H
#define FORMAT_H

#include "binary.h"
#include "core/error.h"

#define X_EXEC "application/x-executable"
#define X_PIE_EXEC "application/x-pie-executable"
#define X_SHAREDLIB "application/x-sharedlib"
#define X_MACH_BIN "application/x-mach-binary"
#define X_DOSEXEC "application/x-dosexec"
#define X_PORTEXEC "application/vnd.microsoft.portable-executable"

typedef struct FormatHandler {
  const char *name;
  BinaryFormat format;

  // Loader function
  BError (*load)(BinaryFile *bin);

  // Print function
  void (*print)(void *parsed_data);
} FormatHandler;

BinaryFile *load_binary(const char *path);

#endif // FORMAT_H
