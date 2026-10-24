#ifndef LATTICA_MATRICT_GUARD_H
#define LATTICA_MATRICT_GUARD_H
#include <stddef.h>
/* Internal C-only unwind, contained by the adapter; never crosses a Rust frame. */
_Noreturn void lattica_matrict_abort(void);
#define LATTICA_NEED_BYTES(cursor, buffer, count) do { \
  if ((size_t)((cursor) - (buffer)) > sizeof(buffer) || \
      (size_t)(count) > sizeof(buffer) - (size_t)((cursor) - (buffer))) \
    lattica_matrict_abort(); \
} while (0)
#endif
