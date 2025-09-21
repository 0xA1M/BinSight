#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "core/error.h"
#include "core/mem.h"

static uintptr_t align_forward(uintptr_t ptr, size_t alignment) {
  assert(IS_POWER_2(alignment));

  uintptr_t modulo = ptr & (alignment - 1);
  if (modulo != 0)
    ptr += alignment - modulo;

  return ptr;
}

static Chunk *allocate_new_chunk(size_t cap) {
  Chunk *chunk = (Chunk *)calloc(1, sizeof(Chunk) + cap);
  if (chunk == NULL) {
    char err_buf[256] = "";
    strerror_r(errno, err_buf, CSTR_LEN(err_buf));
    LOG_ERR("Failed to allocate new chunk with capacity %zu: %s", cap, err_buf);
    return NULL;
  }

  chunk->data = (uint8_t *)(chunk + 1);
  chunk->cap = cap;
  chunk->used = 0;
  chunk->next = NULL;

  return chunk;
}

Arena *arena_init(void) {
  Arena *arena = (Arena *)calloc(1, sizeof(Arena));
  if (arena == NULL) {
    char err_buf[256] = "";
    strerror_r(errno, err_buf, CSTR_LEN(err_buf));
    LOG_ERR("Failed to create arena: %s", err_buf);
    return NULL;
  }

  arena->head = allocate_new_chunk(CHUNK_SIZE);
  if (arena->head == NULL) {
    free(arena);
    return NULL;
  }

  arena->current = arena->head;
  return arena;
}

void arena_destroy(Arena *arena) {
  if (arena == NULL)
    return;

  Chunk *chunk = arena->head;
  while (chunk != NULL) {
    Chunk *next_chunk = chunk->next;
    free(chunk);
    chunk = next_chunk;
  }

  free(arena);
}

void *arena_alloc_align(Arena *arena, size_t size, size_t alignment) {
  if (arena == NULL) {
    LOG_ERR("Arena pointer is NULL");
    return NULL;
  }

  ASSERT_RET_VAL(arena, size > 0, NULL, ERR_ARG_INVALID,
                 "Allocation size must be greater than 0");
  ASSERT_RET_VAL(arena, alignment > 0 && IS_POWER_2(alignment), NULL,
                 ERR_MEM_ALIGNMENT_INVALID,
                 "Alignment must be non-zero power of 2");

  uintptr_t cur_ptr = (uintptr_t)arena->current->data + arena->current->used;
  uintptr_t aligned_ptr = align_forward(cur_ptr, alignment);
  size_t offset = aligned_ptr - (uintptr_t)arena->current->data;

  if (offset + size <= arena->current->cap) {
    arena->current->used = offset + size;
    return (void *)aligned_ptr;
  }

  size_t min_cap = size + alignment - 1;
  size_t cap = MAX(min_cap, CHUNK_SIZE);
  Chunk *new_chunk = (Chunk *)allocate_new_chunk(cap);
  ASSERT_RET_VAL(arena, new_chunk != NULL, NULL, ERR_MEM_ALLOC_FAILED,
                 "Failed to allocate new chunk for arena");

  uintptr_t new_ptr = (uintptr_t)new_chunk->data;
  uintptr_t new_aligned = align_forward(new_ptr, alignment);
  size_t new_offset = new_aligned - new_ptr;

  ASSERT_RET_VAL(
      arena, new_offset + size <= new_chunk->cap, NULL, ERR_MEM_OUT_OF_BOUNDS,
      "Arena allocation out of bounds: requested size=%zu (offset=%zu) "
      "exceeds chunk capacity=%zu (cap=%zu, alignment=%zu)",
      size, new_offset, new_offset + size, new_chunk->cap, alignment);

  new_chunk->used = new_offset + size;
  arena->current->next = new_chunk;
  arena->current = new_chunk;

  return (void *)new_aligned;
}

void *arena_alloc(Arena *arena, size_t size) {
  if (arena == NULL) {
    LOG_ERR("Arena pointer is NULL");
    return NULL;
  }

  return arena_alloc_align(arena, size, DEFAULT_ALIGNMENT);
}

void *arena_alloc_array(Arena *arena, size_t count, size_t size) {
  if (arena == NULL) {
    LOG_ERR("Arena pointer is NULL");
    return NULL;
  }

  if (count > 0 && size > SIZE_MAX / count)
    ASSERT_RET_VAL(
        arena, false, NULL, ERR_ARG_OUT_OF_RANGE,
        "Integer overflow detected in array allocation (count=%zu, size=%zu)",
        count, size);

  return arena_alloc_align(arena, count * size, DEFAULT_ALIGNMENT);
}

const char *arena_strdup(Arena *arena, const char *str, size_t len) {
  if (arena == NULL) {
    LOG_ERR("Arena pointer is NULL");
    return NULL;
  }

  ASSERT_RET_VAL(arena, str != NULL, NULL, ERR_ARG_NULL,
                 "Source string is NULL");
  ASSERT_RET_VAL(arena, len > 0, NULL, ERR_ARG_INVALID,
                 "String length must be greater than 0");

  char *str_dup = (char *)arena_alloc_array(arena, len + 1, sizeof(char));
  ASSERT_RET_VAL(arena, str_dup != NULL, NULL, ERR_MEM_ALLOC_FAILED,
                 "Failed to allocate memory for string duplication");

  memcpy(str_dup, str, len);
  str_dup[len] = '\0';

  return (const char *)str_dup;
}

String string_new(Arena *arena, const char *cstr, uint64_t len) {
  if (cstr == NULL || len == 0)
    return EMPTY_STR;

  const char *str_dup = arena_strdup(arena, cstr, len);
  if (str_dup == NULL)
    return EMPTY_STR;

  return (String){.str = str_dup, .len = len};
}

bool string_eq(String s1, String s2) {
  if (s1.len != s2.len)
    return false;

  return memcmp(s1.str, s2.str, s1.len) == 0;
}
