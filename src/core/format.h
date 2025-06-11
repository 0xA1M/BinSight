#ifndef FORMAT_H
#define FORMAT_H

#include "binary.h"

#define X_EXEC "application/x-executable"
#define X_PIE_EXEC "application/x-pie-executable"
#define X_SHAREDLIB "application/x-sharedlib"
#define X_MACH_BIN "application/x-mach-binary"
#define X_DOSEXEC "application/x-dosexec"
#define X_PORTEXEC "application/vnd.microsoft.portable-executable"

BinaryFile *load_binary(const char *path);

#endif // FORMAT_H
