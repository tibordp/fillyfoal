/* The process dumped by make-core.sh: static, no libc, waits in a pause
 * system call (ppoll with no descriptors and no timeout) so gdb's gcore
 * can attach. */

static const char filly_marker[] = "fillyfoal core fixture";
long filly_counter = 3;

void _start(void)
{
    for (;;) {
        filly_counter += filly_marker[0];
        __asm__ volatile("mov x0, #0\n\tmov x1, #0\n\tmov x2, #0\n\tmov x3, #0\n\t"
                         "mov x8, #73\n\tsvc #0" /* ppoll */
                         ::: "x0", "x1", "x2", "x3", "x8", "memory");
    }
}
