#include <stdio.h>

static int square(int x) { return x * x; }

static int classify(int n) {
    if (n % 3 == 0)
        return 0;
    if (n % 3 == 1)
        return 1;
    return 2;
}

int main(void) {
    int counts[3] = {0, 0, 0};
    long total = 0;
    for (int i = 0; i < 10; i++) {
        counts[classify(i)]++;
        total += square(i);
    }
    printf("%d %d %d %ld\n", counts[0], counts[1], counts[2], total);
    return 0;
}
