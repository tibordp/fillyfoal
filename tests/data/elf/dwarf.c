/* Source of tests/fixtures/external/elf/x86_64-dwarf5 and
 * aarch64-gcc-dwarf4 (see make-dwarf.sh): a freestanding program whose
 * debug information covers the usual DWARF shapes (base, pointer, array,
 * struct, union, enum, typedef and function types; inlined calls; variables
 * whose locations change, so location and range lists are needed). */

typedef unsigned long filly_size;

enum filly_kind { FILLY_SQUARE = 1, FILLY_CIRCLE = 2, FILLY_LINE = -1 };

struct filly_point {
    int x, y;
};

union filly_value {
    int i;
    float f;
    unsigned char bytes[4];
};

struct filly_shape {
    enum filly_kind kind;
    struct filly_point corners[2];
    union filly_value weight;
    unsigned flags : 3;
    const char *name;
    struct filly_shape *next;
};

typedef int (*filly_measure)(const struct filly_shape *);

static struct filly_shape filly_shapes[3] = {
    { FILLY_SQUARE, { { 0, 0 }, { 2, 2 } }, { 1 }, 1, "square", 0 },
    { FILLY_CIRCLE, { { 1, 1 }, { 3, 3 } }, { 2 }, 2, "circle", 0 },
    { FILLY_LINE, { { 0, 1 }, { 4, 1 } }, { 3 }, 4, "line", 0 },
};

volatile int filly_sink;

static inline int filly_width(const struct filly_shape *s)
{
    return s->corners[1].x - s->corners[0].x;
}

static int filly_area(const struct filly_shape *s)
{
    int w = filly_width(s);
    switch (s->kind) {
    case FILLY_SQUARE:
        return w * w;
    case FILLY_CIRCLE:
        return 3 * w * w;
    default:
        return 0;
    }
}

__attribute__((noinline)) static filly_size filly_total(filly_measure m, int n)
{
    filly_size total = 0;
    for (int i = 0; i < n; i++) {
        int a = m(&filly_shapes[i]);
        if (a > 0)
            total += (filly_size)a;
        filly_sink = a;
    }
    return total;
}

void filly_start(void)
{
    filly_shapes[0].next = &filly_shapes[1];
    filly_sink = (int)filly_total(filly_area, 3);
    for (;;)
        ;
}
