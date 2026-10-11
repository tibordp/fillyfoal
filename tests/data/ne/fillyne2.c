/* The second code segment of fillyne.exe. */
#include <windows.h>

extern int filly_counter;

int FAR PASCAL filly_value(void)
{
    return filly_counter * 2;
}
