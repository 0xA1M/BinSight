#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "core/error.h"

static String dup_fmt(Arena *arena, const char *fmt, va_list ap) {
  if (arena == NULL)
    return EMPTY_STR;

  va_list aq;
  va_copy(aq, ap);

  int needed = vsnprintf(NULL, 0, fmt, aq);
  va_end(aq);

  if (needed < 0)
    return EMPTY_STR;

  String buf = string_new(arena, "", needed + 1);
  if (IS_STR_EMPTY(buf))
    return EMPTY_STR;

  vsnprintf((char *)buf.str, needed + 1, fmt, ap);

  return buf;
}

BError berr_new(Arena *arena, BErrorCode code, const char *fmt,
                const char *file, int line, const char *func, ...) {
  String user_msg = EMPTY_STR;
  if (fmt != NULL) {
    va_list ap;
    va_start(ap, func);
    user_msg = dup_fmt(arena, fmt, ap);
    va_end(ap);
  }

  String code_str = berr_code_to_str(code);
  size_t total_len = code_str.len + 2; // For "[]"
  if (!IS_STR_EMPTY(user_msg)) {
    total_len += 1; // For the space before user_msg
    total_len += user_msg.len;
  }
  total_len += 1; // For null terminator

  String buf = EMPTY_STR;
  if (arena != NULL)
    buf = string_new(arena, "", total_len);

  if (IS_STR_EMPTY(buf))
    return (BError){
        .code = ERR_MEM_ALLOC_FAILED,
        .err_msg = EMPTY_STR,
        .file = file,
        .line = line,
        .func = func,
    };

  if (!IS_STR_EMPTY(user_msg))
    snprintf((char *)buf.str, total_len, "[" STR "] %.*s", (int)code_str.len,
             code_str.str, (int)user_msg.len, user_msg.str);
  else
    snprintf((char *)buf.str, total_len, "[" STR "]", (int)code_str.len,
             code_str.str);

  return (BError){
      .code = code, .file = file, .line = line, .func = func, .err_msg = buf};
}

BError berr_from_errno(Arena *arena, BErrorCode code, const char *fmt,
                       const char *file, int line, const char *func, ...) {
  String user_msg = EMPTY_STR;
  if (fmt != NULL) {
    va_list ap;
    va_start(ap);
    user_msg = dup_fmt(arena, fmt, ap);
    va_end(ap);
  }

  String code_str = berr_code_to_str(code);
  char errno_str[256] = "";
  strerror_r(errno, errno_str, CSTR_LEN(errno_str));

  size_t total_len = code_str.len + 2; // For "[]"
  if (!IS_STR_EMPTY(user_msg)) {
    total_len += 1; // For the space after ']' and before user_msg
    total_len += user_msg.len;
    total_len += 2; // For ": "
  } else {
    total_len += 1; // For the space after ']' and before errno_str
  }
  total_len += strlen(errno_str);
  total_len += 1; // For null terminator

  String buf = EMPTY_STR;
  if (arena != NULL)
    buf = string_new(arena, "", total_len);

  if (IS_STR_EMPTY(buf))
    return (BError){.code = ERR_MEM_ALLOC_FAILED, .err_msg = EMPTY_STR};

  if (!IS_STR_EMPTY(user_msg))
    snprintf((char *)buf.str, total_len, "[" STR "] " STR ": %s",
             (int)code_str.len, code_str.str, (int)user_msg.len, user_msg.str,
             errno_str);
  else
    snprintf((char *)buf.str, total_len, "[" STR "] %s", (int)code_str.len,
             code_str.str, errno_str);

  return (BError){
      .code = code, .file = file, .line = line, .func = func, .err_msg = buf};
}

String berr_code_to_str(BErrorCode code) {
  for (size_t i = 0; i < ARR_COUNT(BErrorCodeStrTable); i++)
    if (BErrorCodeStrTable[i].id == code)
      return (String){BErrorCodeStrTable[i].name,
                      strlen(BErrorCodeStrTable[i].name)};

  return CONST_STR("Unrecognized error code");
}

String berr_msg(const BError *err) {
  if (err == NULL || err->err_msg.len == 0 || err->err_msg.str == NULL)
    return CONST_STR("(no error message)");

  return err->err_msg;
}

void berr_print(const BError *err) {
  if (err == NULL)
    return;

  String err_msg = berr_msg(err);
  fprintf(stderr, "Error: " STR, (int)err_msg.len, err_msg.str);
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
