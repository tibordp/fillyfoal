/* fillyfoal test fixture: exe that imports fixture_lib.dll by name and by ordinal. */
#include <stdio.h>

__declspec(dllimport) int fillyfoal_add(int a, int b);
__declspec(dllimport) const char *fillyfoal_name(void);
__declspec(dllimport) int fillyfoal_hidden(void); /* imported by ordinal 7 */

int main(void)
{
    printf("%s: %d %d\n", fillyfoal_name(), fillyfoal_add(2, 3), fillyfoal_hidden());
    return 0;
}
