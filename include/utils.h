#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

#include "core/binary.h"

#if defined(_WIN32) || defined(_WIN64)
#include <io.h>
#define stat_func _stat64
#else
#include <unistd.h>
#define stat_func stat
#endif

#define ARR_COUNT(x) (sizeof(x) / sizeof((x)[0]))
#define CSTR_LEN(x) ((sizeof(x) / sizeof((x)[0])) - 1)

#define not_implemented() printf("Not Implemented!\n");

#define BYTE 1
#define WORD 2
#define DWORD 4
#define QWORD 8

BinaryFormat get_binary_format(const char *mime_str);
const char *print_binary_format(BinaryFormat fmt);
long get_file_size(FILE *f);
bool is_file_exist(const char *path);
void print_hex(const unsigned char *buf, size_t len);
