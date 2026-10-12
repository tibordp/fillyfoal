/* A tiny MinGW-w64 image without a C runtime: GNU ld keeps the COFF symbol
   table and its string table after the last section (and with -g, DWARF
   sections whose long names live in that string table). */
int filly_counter = 3;
static const char filly_greeting[] = "fillyfoal";

static int filly_twice(int x) { return x * 2; }

__declspec(dllexport) int filly_value(void) { return filly_twice(filly_counter); }

int filly_start(void) {
    int sum = 0;
    for (int i = 0; filly_greeting[i]; i++)
        sum += filly_greeting[i];
    return sum + filly_value();
}
