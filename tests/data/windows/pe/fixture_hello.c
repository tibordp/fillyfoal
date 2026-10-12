/* fillyfoal test fixture: tiny console program (synthetic content only). */
#include <stdio.h>

static const char fillyfoal_banner[] = "fillyfoal test: hello from a PE fixture";

int main(int argc, char **argv)
{
    (void)argv;
    printf("%s (argc=%d)\n", fillyfoal_banner, argc);
    return 0;
}
