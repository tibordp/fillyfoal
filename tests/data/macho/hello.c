#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *greetings[] = {"hello", "bonjour", "hola"};
int counter = 3;
__thread int tls_counter = 1;

const char *pick(int i) { return greetings[i % 3]; }

int main(int argc, char **argv) {
    for (int i = 0; i < counter; i++)
        printf("%s, world (%d)\n", pick(i + argc), tls_counter++);
    char *p = strdup(argv[0]);
    free(p);
    return 0;
}
