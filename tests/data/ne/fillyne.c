/* A small Windows 3.x program for the NE fixture, built without any C
   runtime (make.sh): two code segments (a far call between them is an
   internal reference), a far data segment whose selector the code loads
   (a SEGMENT fixup), the automatic data segment, and
   imports by ordinal and by name (the IMPORT directives in make.sh). The
   entry point is filly_start; the file is not meant to run. */

typedef unsigned short WORD;

extern int __far __pascal FillyBox(void __far *hwnd, const char __far *text,
                                   const char __far *title, WORD flags);
extern void __far __pascal FillyExit(int code);
extern int __far __pascal FillyHelper(int x);
extern int __far __pascal filly_value(void);

int filly_counter = 3;
static char filly_title[] = "fillyfoal";
int __far filly_far = 5;

void __far filly_start(void)
{
    int v = filly_value() + filly_counter + filly_far;
    FillyBox(0, filly_title, filly_title, 0);
    FillyExit(FillyHelper(v));
}
