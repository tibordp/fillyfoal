/* A small Windows 3.x program for the NE fixtures: two code segments (a far
   call between them is an internal reference), imports by ordinal (USER's
   MessageBox through windows.lib) and by name (the IMPORT directive in
   make.sh), and a data segment whose address the code loads. */
#include <windows.h>

int filly_counter = 3;
static char filly_title[] = "fillyfoal";

int FAR PASCAL filly_value(void);
int FAR PASCAL FillyHelper(int x);

int PASCAL WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show)
{
    char buf[16];
    wsprintf(buf, "%d", filly_value() + filly_counter);
    MessageBox(NULL, buf, filly_title, MB_OK);
    return FillyHelper(0);
}
