#ifndef UTILS_H
#define UTILS_H

#include "binary.h"

#define ARR_COUNT(x) (sizeof(x) / sizeof((x)[0]))
#define CSTR_LEN(x) ((sizeof(x) / sizeof((x)[0])) - 1)

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define IS_POWER_2(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

#define NOT_IMPLEMENTED() printf("Not Implemented!\n");

#define BYTE 1
#define WORD 2
#define DWORD 4
#define QWORD 8

BinaryFormat get_binary_format(const char *mime_str);
const char *print_binary_format(BinaryFormat fmt);

#endif // UTILS_H
