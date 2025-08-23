#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "core/error.h"
#include "core/mem.h"
#include "core/utils.h"

static char *dup_fmt(Arena *arena, const char *fmt, va_list ap) {
  if (arena == NULL)
    return NULL;

  va_list aq;
  va_copy(aq, ap);

  int needed = vsnprintf(NULL, 0, fmt, aq);
  va_end(aq);

  if (needed < 0)
    return NULL;

  char *buf = arena_alloc(arena, needed + 1);
  if (buf == NULL)
    return NULL;

  vsnprintf(buf, needed + 1, fmt, ap);
  return buf;
}

BError berr_new(Arena *arena, BErrorCode code, const char *fmt,
                const char *file, int line, const char *func, ...) {
  char *user_msg = NULL;
  if (fmt != NULL) {
    va_list ap;
    va_start(ap, func);
    user_msg = dup_fmt(arena, fmt, ap);
    va_end(ap);
  }

  const char *code_str = berr_code_to_str(code);

  size_t total_len = strlen(code_str) + 3; // For "[] "
  if (user_msg != NULL)
    total_len += strlen(user_msg);

  total_len += 1; // For null terminator

  char *buf = NULL;
  if (arena != NULL)
    buf = arena_alloc(arena, total_len);

  if (buf == NULL)
    return (BError){.code = ERR_MEM_ALLOC_FAILED,
                    .err_msg = NULL,
                    .file = file,
                    .line = line,
                    .func = func};

  if (user_msg)
    snprintf(buf, total_len, "[%s] %s", code_str, user_msg);
  else
    snprintf(buf, total_len, "[%s]", code_str);

  return (BError){
      .code = code, .file = file, .line = line, .func = func, .err_msg = buf};
}

BError berr_from_errno(Arena *arena, BErrorCode code, const char *fmt,
                       const char *file, int line, const char *func, ...) {
  char *user_msg = NULL;
  if (fmt != NULL) {
    va_list ap;
    va_start(ap);
    user_msg = dup_fmt(arena, fmt, ap);
    va_end(ap);
  }

  const char *code_str = berr_code_to_str(code);

  char errno_str[256] = "";
  strerror_r(errno, errno_str, CSTR_LEN(errno_str));

  size_t total_len =
      strlen(code_str) + 3 +                  // For "[] "
      (user_msg ? strlen(user_msg) + 2 : 0) + // For user_msg ": "
      strlen(errno_str) + 1;                  // For ": %s" and null terminator

  char *buf = NULL;
  if (arena != NULL)
    buf = arena_alloc(arena, total_len);

  if (buf == NULL)
    return (BError){.code = ERR_MEM_ALLOC_FAILED, .err_msg = NULL};

  if (user_msg)
    snprintf(buf, total_len, "[%s] %s: %s", code_str, user_msg, errno_str);
  else
    snprintf(buf, total_len, "[%s] %s", code_str, errno_str);

  return (BError){
      .code = code, .file = file, .line = line, .func = func, .err_msg = buf};
}

const char *berr_code_to_str(BErrorCode code) {
  for (size_t i = 0; i < ARR_COUNT(BErrorCodeStrTable); i++)
    if (BErrorCodeStrTable[i].id == code)
      return BErrorCodeStrTable[i].name;

  return "Unrecognized error code";
}

const char *berr_msg(const BError *err) {
  return err && err->err_msg ? err->err_msg : "(no error message)";
}

void berr_print(const BError *err) {
  if (err == NULL)
    return;

  fprintf(stderr, "Error: %s", berr_msg(err));
  if (err->file && err->func)
    fprintf(stderr, " at %s:%d (in %s)", err->file, err->line, err->func);
  fprintf(stderr, "\n");
}

void log_error(const char *fmt, ...) {
  if (fmt == NULL)
    return;

  va_list args;
  va_start(args, fmt);

  fprintf(stderr, "Error: ");
  vfprintf(stderr, fmt, args);
  fprintf(stderr, " at %s:%d (in %s)\n", __FILE__, __LINE__, __func__);

  va_end(args);
}
