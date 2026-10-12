/* The second code segment of fillyne.exe. */

extern int filly_counter;

int __far __pascal filly_value(void)
{
    return filly_counter * 2;
}
