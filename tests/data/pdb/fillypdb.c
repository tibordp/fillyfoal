/* Source of tests/fixtures/external/pdb/lld-link.pdb (see make.sh). */

enum shape { SQUARE = 1, CIRCLE = 2 };

struct point {
    int x, y;
};

struct figure {
    enum shape kind;
    struct point origin;
    unsigned size;
};

int filly_counter = 3;
static const char filly_name[] = "fillyfoal";

static int area(const struct figure *f)
{
    int s = (int)f->size;
    return f->kind == SQUARE ? s * s : 3 * s * s;
}

int filly_main(void)
{
    struct figure f = { SQUARE, { 1, 2 }, 4 };
    filly_counter += area(&f) + filly_name[0];
    return filly_counter;
}
