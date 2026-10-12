/* Small debug-info test program: a struct and an inline function from a
   header, locals kept in registers, a loop and a static helper, so the
   DWARF has decl_file references to two files, register locations and
   call frame information. */
#include "shapes.h"

int shape_sides = 4;
int shape_counter = 2;

static int twice(int v) { return v * 2; }

int shape_area(const struct point *corners, int count) {
    int area = 0;
    for (int i = 0; i < count; i++) {
        const struct point *a = &corners[i];
        const struct point *b = &corners[(i + 1) % count];
        area += a->x * b->y - b->x * a->y;
    }
    return area < 0 ? -area : area;
}

int shape_start(void) {
    struct point square[4] = {{0, 0}, {4, 0}, {4, 4}, {0, 4}};
    shape_counter += point_dot(&square[1], &square[2]);
    return twice(shape_area(square, shape_sides)) + shape_counter;
}

int main(void) { return shape_start() & 0x7f; }
