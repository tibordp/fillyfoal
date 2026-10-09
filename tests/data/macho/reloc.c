/* An object file exercising relocations: calls, GOT loads, pointers,
 * differences and an auto-link option. */
#pragma comment(lib, "z")

extern int external_value;
extern int external_function(int);

static int local_table[4] = {1, 2, 3, 4};
int *table_pointer = &local_table[2];
long difference = (long)((char *)&local_table[3] - (char *)&local_table[0]);
const char *message = "relocated";

int use(int x) {
    switch (x) {
    case 0: return external_function(local_table[0]);
    case 1: return external_value;
    case 2: return local_table[x];
    case 3: return *table_pointer + 7;
    case 4: return (int)difference;
    default: return message[x & 7];
    }
}
