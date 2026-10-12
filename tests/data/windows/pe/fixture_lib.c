/* fillyfoal test fixture: DLL with named, ordinal-only and forwarded exports,
   and a delay-loaded import of version.dll (synthetic content only). */
#include <windows.h>

int fillyfoal_add(int a, int b) { return a + b; }
int fillyfoal_mul(int a, int b) { return a * b; }
const char *fillyfoal_name(void) { return "fillyfoal test"; }

/* Exported by ordinal only (NONAME in the .def file). */
int fillyfoal_hidden(void) { return 42; }

int fillyfoal_data_value = 1234;

/* Calls into version.dll, which is delay-loaded (/DELAYLOAD:version.dll). */
DWORD fillyfoal_version_size(const wchar_t *path)
{
    DWORD handle = 0;
    return GetFileVersionInfoSizeW(path, &handle);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reason; (void)reserved;
    return TRUE;
}
