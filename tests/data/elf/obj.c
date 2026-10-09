extern int puts(const char *);
extern int external_counter;
static int calls;
int table[4] = {1, 2, 3, 4};
const char *message = "relocate me";
int compute(int x) { calls++; return x * table[x & 3] + external_counter; }
void hello(void) { puts(message); compute(calls); }
