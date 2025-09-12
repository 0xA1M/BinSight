#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include "core/binary.h"
#include "core/error.h"

BError load_elf(Binary *bin);

#endif // ELF_LOADER_H
