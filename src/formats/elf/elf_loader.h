#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include <stdio.h>

#include "core/binary.h"

int load_elf(FILE *f, BinaryFile *bin);

#endif // ELF_LOADER_H
