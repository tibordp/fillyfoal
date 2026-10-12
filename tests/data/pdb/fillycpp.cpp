// A small C++ program for tests/fixtures/external/pdb/lld-link-cpp.pdb
// (make.sh): classes with a base class, virtual and overloaded methods, a
// static member, a nested enum, pointers, references, an array, a bitfield
// and a union, so the TPI stream holds most kinds of type records and the
// module stream holds locals, inline sites and their line tables.

namespace filly {

struct Shape {
    enum class Kind : unsigned char { Square = 1, Circle = 2 };
    Kind kind;
    unsigned flags : 3;
    unsigned visible : 1;
    static int count;
    virtual int area() const { return 0; }
    __declspec(noinline) int scaled(int by) const { return area() * by; }
    int scaled(const Shape &other) const { return area() + other.area(); }
};

int Shape::count = 0;

struct Square : Shape {
    int side;
    explicit Square(int s) : side(s) { kind = Kind::Square; ++count; }
    int area() const override { return side * side; }
};

union Value {
    int i;
    float f;
    const char *s;
};

static inline int sum(const int *values, int n)
{
    int total = 0;
    for (int i = 0; i < n; i++)
        total += values[i];
    return total;
}

} // namespace filly

extern "C" int filly_main(void)
{
    int values[4] = {1, 2, 3, 4};
    filly::Square square(3);
    const filly::Shape &shape = square;
    filly::Value v;
    v.i = shape.scaled(2) + shape.scaled(square);
    return filly::sum(values, 4) + v.i + filly::Shape::count;
}
