/* A small dylib: functions, data, a weak definition and a thread-local. */
#include <string.h>

int filly_answer(void) { return 42; }

const char filly_name[] = "fillyfoal";

int filly_counter = 7;

__attribute__((weak)) int filly_weak(int x) { return x * 2; }

__thread long filly_tls = 5;

size_t filly_len(const char *s) { return strlen(s) + (size_t)filly_counter; }
