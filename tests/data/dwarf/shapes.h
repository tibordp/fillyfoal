/* Declarations in a second file, so DW_AT_decl_file names more than the
   compilation unit's own source. */
struct point {
    int x, y;
};

static inline int point_dot(const struct point *a, const struct point *b) {
    return a->x * b->x + a->y * b->y;
}

int shape_area(const struct point *corners, int count);
