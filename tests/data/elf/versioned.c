/* A shared object with symbol versions (make-dynamic.sh): filly_value has
 * an old version FILLY_1.0 and the default FILLY_2.0, which inherits from
 * it (versioned.map), so the library has a version definition section. */

int filly_count = 3;

int filly_value_old(void) { return 1; }
int filly_value_new(void) { return filly_count * 2; }

__asm__(".symver filly_value_old, filly_value@FILLY_1.0");
__asm__(".symver filly_value_new, filly_value@@FILLY_2.0");
