#include "leptjson.h"
#include <assert.h> /* assert() */
#include <errno.h>  /* errno, ERANGE */
#include <math.h>   /* HUGE_VAL */
#include <stdlib.h> /* strtod() malloc() realloc() free() */
#include <string.h>  /* memcpy() */
#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#define EXPECT(c, ch)                                                          \
  do {                                                                         \
    assert(*c->json == (ch));                                                  \
    c->json++;                                                                 \
  } while (0)
#define ISDIGIT(ch) ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch) ((ch) >= '1' && (ch) <= '9')
#define PUTC(c, ch) do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)

typedef struct {
  const char* json;
  char* stack;
  size_t size, top;
} lept_context;

static void* lept_context_push(lept_context* c, size_t size) {
  void* ret;
  assert(size > 0);
  if (c->top + size >= c->size) {
    if (c->size == 0)
      c->size = LEPT_PARSE_STACK_INIT_SIZE;
    while (c->top + size >= c->size)
      c->size += c->size >> 1;  /* c->size * 1.5 */
    c->stack = (char*)realloc(c->stack, c->size);
  }
  ret = c->stack + c->top;
  c->top += size;
  return ret;
}

static void* lept_context_pop(lept_context* c, size_t size) {
  assert(c->top >= size);
  return c->stack + (c->top -= size);
}

static void lept_parse_whitespace(lept_context* c) {
  const char* p = c->json;
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
    p++;
  c->json = p;
}

static int lept_parse_literal(lept_context* c, lept_value* v) {
  switch (*c->json) {
  case 'n':
    if (c->json[1] != 'u' || c->json[2] != 'l' || c->json[3] != 'l')
      return LEPT_PARSE_INVALID_VALUE;
    c->json += 4;
    v->type = LEPT_NULL;
    return LEPT_PARSE_OK;
  case 't':
    if (c->json[1] != 'r' || c->json[2] != 'u' || c->json[3] != 'e')
      return LEPT_PARSE_INVALID_VALUE;
    c->json += 4;
    v->type = LEPT_TRUE;
    return LEPT_PARSE_OK;
  case 'f':
    if (c->json[1] != 'a' || c->json[2] != 'l' || c->json[3] != 's' ||
      c->json[4] != 'e')
      return LEPT_PARSE_INVALID_VALUE;
    c->json += 5;
    v->type = LEPT_FALSE;
    return LEPT_PARSE_OK;
  default:
    return LEPT_PARSE_INVALID_VALUE;
  }
}

static int lept_parse_number(lept_context* c, lept_value* v) {
  const char* end = c->json;
  if (*end == '-')
    end++;
  if (*end == '0')
    end++;
  else {
    if (!ISDIGIT1TO9(*end))
      return LEPT_PARSE_INVALID_VALUE;
    for (end++; ISDIGIT(*end); end++)
      ;
  }
  if (*end == '.') {
    end++;
    if (!ISDIGIT(*end))
      return LEPT_PARSE_INVALID_VALUE;
    for (end++; ISDIGIT(*end); end++)
      ;
  }
  if (*end == 'e' || *end == 'E') {
    end++;
    if (*end == '+' || *end == '-')
      end++;
    if (!ISDIGIT(*end))
      return LEPT_PARSE_INVALID_VALUE;
    for (end++; ISDIGIT(*end); end++)
      ;
  }
  errno = 0;
  v->u.n = strtod(c->json, NULL);
  if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL))
    return LEPT_PARSE_NUMBER_TOO_BIG;
  c->json = end;
  v->type = LEPT_NUMBER;
  return LEPT_PARSE_OK;
}

static int lept_parse_string(lept_context* c, lept_value* v) {
  size_t head = c->top, len;
  EXPECT(c, '\"');
  const char* p;
  p = c->json;
  while (1) {
    char ch = *p++, chh;
    switch (ch) {
    case '\"':
      len = c->top - head;
      lept_set_string(v, (const char*)lept_context_pop(c, len), len);
      c->json = p;
      return LEPT_PARSE_OK;
    case '\0':
      c->top = head;
      return LEPT_PARSE_MISS_QUOTATION_MARK;
    case '\\':
      chh = *p++;
      if (chh == '\\')
        PUTC(c, '\\');
      else if (chh == '\"')
        PUTC(c, '\"');
      else if (chh == '/')
        PUTC(c, '/');
      else if (chh == 'b')
        PUTC(c, '\b');
      else if (chh == 'f')
        PUTC(c, '\f');
      else if (chh == 'n')
        PUTC(c, '\n');
      else if (chh == 'r')
        PUTC(c, '\r');
      else if (chh == 't')
        PUTC(c, '\t');
      else {
        c->top = head;
        return LEPT_PARSE_INVALID_STRING_ESCAPE;
      }
      break;
    default:
      if ((unsigned char)ch < 0x20) {
        // for all unprintable char
        c->top = head;
        return LEPT_PARSE_INVALID_STRING_CHAR;
      }
      PUTC(c, ch);
    }
  }
}

static int lept_parse_value(lept_context* c, lept_value* v) {
  switch (*c->json) {
  case 'n':
    return lept_parse_literal(c, v);
  case 't':
    return lept_parse_literal(c, v);
  case 'f':
    return lept_parse_literal(c, v);
  case '\"':
    return lept_parse_string(c, v);
  case '\0':
    return LEPT_PARSE_EXPECT_VALUE;
  default:
    return lept_parse_number(c, v);
  }
}

int lept_parse(lept_value* v, const char* json) {
  lept_context c;
  int ret;
  assert(v != NULL);
  c.json = json;
  c.stack = NULL;
  c.size = 0;
  c.top = 0;
  lept_init(v);
  lept_parse_whitespace(&c);
  if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
    lept_parse_whitespace(&c);
    if (*c.json) {
      v->type = LEPT_NULL;
      ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
    }
  }
  assert(c.top == 0);
  free(c.stack);
  return ret;
}

void lept_free(lept_value* v) {
  assert(v != NULL);
  if (v->type == LEPT_STRING)
    free(v->u.s.s);
  v->type = LEPT_NULL;
}

lept_type lept_get_type(const lept_value* v) {
  assert(v != NULL);
  return v->type;
}

int lept_get_boolean(const lept_value* v) {
  assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
  return v->type;
}

void lept_set_boolean(lept_value* v, lept_type b) {
  assert(v != NULL);
  v->type = b;
}

double lept_get_number(const lept_value* v) {
  assert(v != NULL && v->type == LEPT_NUMBER);
  return v->u.n;
}

void lept_set_number(lept_value* v, double n) {
  assert(v != NULL);
  v->u.n = n;
  v->type = LEPT_NUMBER;
}

void lept_set_string(lept_value* v, const char* s, size_t len) {
  assert(v != NULL && (s != NULL || len == 0));
  lept_free(v);
  v->u.s.s = (char*)malloc(len + 1);
  memcpy(v->u.s.s, s, len);
  v->u.s.s[len] = '\0';
  v->u.s.len = len;
  v->type = LEPT_STRING;
}

const char* lept_get_string(const lept_value* v) {
  assert(v != NULL && v->type == LEPT_STRING);
  return v->u.s.s;
}

size_t lept_get_string_length(const lept_value* v) {
  assert(v != NULL && v->type == LEPT_STRING);
  return v->u.s.len;
}
