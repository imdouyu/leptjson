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
#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

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

static const char* lept_parse_hex4(const char* p, unsigned* u) {
  unsigned  hex = 0;
  for (size_t i = 0; i < 4; i++) {
    if ('0' <= p[i] && p[i] <= '9')
      hex = 16 * hex + p[i] - '0';
    else if ('A' <= p[i] && p[i] <= 'F')
      hex = 16 * hex + p[i] - 'A' + 10;
    else if ('a' <= p[i] && p[i] <= 'f')
      hex = 16 * hex + p[i] - 'a' + 10;
    else
      return NULL;
  }
  *u = hex;
  p += 4;
  return p;
}

static void lept_encode_utf8(lept_context* c, unsigned u) {
  if (u <= 0x007f) {
    PUTC(c, u & 0xff);
  }
  else if (u <= 0x07ff) {
    PUTC(c, 0xc0 | ((u >> 6) & 0x1f));
    PUTC(c, 0x80 | (u & 0x3f));
  }
  else if (u <= 0xffff) {
    PUTC(c, 0xe0 | ((u >> 12) & 0x0f));
    PUTC(c, 0x80 | ((u >> 6) & 0x3f));
    PUTC(c, 0x80 | (u & 0x3f));
  }
  else if (u <= 0x10ffff) {
    PUTC(c, 0xf0 | ((u >> 18) & 0x07));
    PUTC(c, 0x80 | ((u >> 12) & 0x3f));
    PUTC(c, 0x80 | ((u >> 6) & 0x3f));
    PUTC(c, 0x80 | (u & 0x3f));
  }
}

static int lept_parse_string_raw(lept_context* c, char** str, size_t* len) {
  size_t head = c->top;
  EXPECT(c, '\"');
  const char* p;
  p = c->json;
  while (1) {
    char ch = *p++;
    switch (ch) {
    case '\"':
      *len = c->top - head;
      // lept_set_string(v, (const char*)lept_context_pop(c, len), len);
      *str = (char*)malloc(*len);
      memcpy(*str, (const char*)lept_context_pop(c, *len), *len);
      c->json = p;
      return LEPT_PARSE_OK;
    case '\0':
      STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
    case '\\':
      switch (*p++) {
      case '\\':
        PUTC(c, '\\');
        break;
      case '\"':
        PUTC(c, '\"');
        break;
      case '/':
        PUTC(c, '/');
        break;
      case 'b':
        PUTC(c, '\b');
        break;
      case 'f':
        PUTC(c, '\f');
        break;
      case 'n':
        PUTC(c, '\n');
        break;
      case 'r':
        PUTC(c, '\r');
        break;
      case 't':
        PUTC(c, '\t');
        break;
      case 'u': {
        unsigned u;
        if (!(p = lept_parse_hex4(p, &u)))
          STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
        // parse surrogate pair
        if (0xD800 <= u && u <= 0xDBFF) {
          unsigned l;
          if (*p++ != '\\')
            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
          if (*p++ != 'u')
            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
          if (!(p = lept_parse_hex4(p, &l)))
            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
          if (0xDC00 <= l && l <= 0xDFFF)
            u = 0x10000 + (u - 0xD800) * 0x400 + (l - 0xDC00);
          else
            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
        }
        lept_encode_utf8(c, u);
        break;
      }
      default:
        STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
      }
      break;
    default:
      if ((unsigned char)ch < 0x20) {
        // for all unprintable char
        STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
      }
      PUTC(c, ch);
    }
  }
}

static int lept_parse_string(lept_context* c, lept_value* v) {
  int ret;
  char* s;
  size_t len;
  if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK) {
    lept_set_string(v, s, len);
    free(s);
  }
  return ret;
}

static int lept_parse_value(lept_context* c, lept_value* v);

static int lept_parse_array(lept_context* c, lept_value* v) {
  size_t size = 0;
  int ret;
  EXPECT(c, '[');
  lept_parse_whitespace(c);
  if (*c->json == ']') {
    c->json++;
    v->type = LEPT_ARRAY;
    v->u.a.size = 0;
    v->u.a.e = NULL;
    return LEPT_PARSE_OK;
  }
  while (1) {
    lept_value e;
    lept_init(&e);
    if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK)
      break;
    memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
    size++;
    lept_parse_whitespace(c);
    if (*c->json == ',') {
      c->json++;
      lept_parse_whitespace(c);
    }
    else if (*c->json == ']') {
      c->json++;
      v->type = LEPT_ARRAY;
      v->u.a.size = size;
      size *= sizeof(lept_value);
      memcpy(v->u.a.e = (lept_value*)malloc(size), lept_context_pop(c, size), size);
      return LEPT_PARSE_OK;
    }
    else {
      ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
      break;
    }
  }
  for (size_t i = 0; i < size; i++)
    lept_free((lept_value*)lept_context_pop(c, sizeof(lept_value)));
  return ret;
}

static int lept_parse_object(lept_context* c, lept_value* v) {
  size_t size = 0;
  lept_member m;
  int ret;
  EXPECT(c, '{');
  lept_parse_whitespace(c);
  if (*c->json == '}') {
    c->json++;
    v->type = LEPT_OBJECT;
    v->u.o.size = 0;
    v->u.o.m = NULL;
    return LEPT_PARSE_OK;
  }
  while (1) {
    lept_init(&m.v);
    size_t len = 0;
    char* str;
    if (*c->json == '\"')
      lept_parse_string_raw(c, &str, &len);
    if (len == 0) {
      ret = LEPT_PARSE_MISS_KEY;
      break;
    }
    m.klen = len;
    m.k = (char*)malloc(len + 1);
    memcpy(m.k, str, len);
    free(str);
    m.k[len] = '\0';
    lept_parse_whitespace(c);
    if (*c->json == ':') {
      c->json++;
      lept_parse_whitespace(c);
    }
    else {
      free(m.k);
      ret = LEPT_PARSE_MISS_COLON;
      break;
    }
    if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK)
      break;
    memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
    size++;
    m.k = NULL;
    m.klen = 0;
    lept_parse_whitespace(c);
    if (*c->json == ',') {
      c->json++;
      lept_parse_whitespace(c);
    }
    else if (*c->json == '}') {
      c->json++;
      v->type = LEPT_OBJECT;
      v->u.o.size = size;
      size *= sizeof(lept_member);
      memcpy(v->u.o.m = (lept_member*)malloc(size), lept_context_pop(c, size), size);
      return LEPT_PARSE_OK;
    }
    else {
      ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
      break;
    }
  }
  //free objects in stack
  for (size_t i = 0; i < size; i++) {
    lept_member* member = lept_context_pop(c, sizeof(lept_member));
    free(member->k);
    lept_free(&member->v);
  }
  return ret;
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
  case '[':
    return lept_parse_array(c, v);
  case '{':
    return lept_parse_object(c, v);
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
  switch (v->type)
  {
  case LEPT_STRING:
    free(v->u.s.s);
    break;
  case LEPT_ARRAY:
    for (size_t i = 0; i < v->u.a.size; i++)
      lept_free(&v->u.a.e[i]);
    free(v->u.a.e);
    break;
  case LEPT_OBJECT:
    for (size_t i = 0; i < v->u.o.size; i++) {
      free(v->u.o.m[i].k);
      lept_free(&v->u.o.m[i].v);
    }
    free(v->u.o.m);
    break;
  default:
    break;
  }
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

size_t lept_get_array_size(const lept_value* v) {
  assert(v != NULL && v->type == LEPT_ARRAY);
  return v->u.a.size;
}

lept_value* lept_get_array_element(const lept_value* v, size_t index) {
  assert(v != NULL && v->type == LEPT_ARRAY);
  assert(index < v->u.a.size);
  return &v->u.a.e[index];
}
