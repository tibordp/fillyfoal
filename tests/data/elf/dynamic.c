/* A dynamically linked executable using libfilly.so (make-dynamic.sh): its
 * imports bind to versioned symbols, so it carries version requirements,
 * a PT_INTERP and PLT/GOT relocations. No libc: _start loops forever. */

extern int filly_value(void);
extern int filly_count;

void _start(void)
{
    volatile int x = filly_value() + filly_count;
    (void)x;
    for (;;)
        ;
}
