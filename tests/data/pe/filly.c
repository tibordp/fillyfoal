/* Source of tests/fixtures/external/pe/filly64.dll, filly32.exe and
 * fillyarm64.exe (see make.sh). No C runtime: the image is linked with
 * lld-link /nodefaultlib, so the structures below are the ones the CRT
 * would otherwise provide (TLS directory, load configuration, delay-load
 * helper). */
#include <windows.h>

/* Imports: kernel32 by name, fillyhelp.dll by name and by ordinal. */
__declspec(dllimport) int __stdcall helper_named(int);
__declspec(dllimport) int __stdcall helper_ord(int);
/* Delay-loaded (/delayload:fillydelay.dll). */
__declspec(dllimport) int __stdcall delay_one(int);
__declspec(dllimport) int __stdcall delay_two(int);

/* --- TLS: one thread-local variable and two callbacks --------------------- */
ULONG _tls_index = 0;
#pragma section(".tls", read, write)
#pragma section(".tls$ZZZ", read, write)
__attribute__((section(".tls"))) char _tls_start = 0;
__attribute__((section(".tls$ZZZ"))) char _tls_end = 0;
_Thread_local int filly_counter = 7;

static void NTAPI tls_first(PVOID h, DWORD reason, PVOID r) { (void)h; (void)r; if (reason == DLL_THREAD_ATTACH) filly_counter++; }
static void NTAPI tls_second(PVOID h, DWORD reason, PVOID r) { (void)h; (void)reason; (void)r; }
__attribute__((section(".CRT$XLB"), used)) PIMAGE_TLS_CALLBACK filly_tls_callbacks[] = { tls_first, tls_second, 0 };

__attribute__((used)) const IMAGE_TLS_DIRECTORY _tls_used = {
    (ULONG_PTR)&_tls_start, (ULONG_PTR)&_tls_end, (ULONG_PTR)&_tls_index,
    (ULONG_PTR)filly_tls_callbacks, 0, 0,
};

/* --- Load configuration (the linker fills in the CFG / SEH fields) ------- */
UINT_PTR __security_cookie = (UINT_PTR)0x2B992DDFA232ULL;
#ifdef _WIN64
extern void *__guard_fids_table, *__guard_iat_table, *__guard_longjmp_table, *__guard_eh_cont_table;
extern ULONGLONG __guard_fids_count, __guard_iat_count, __guard_longjmp_count, __guard_eh_cont_count;
void __guard_check_icall_dummy(void) {}
void *__guard_check_icall_fptr = (void *)__guard_check_icall_dummy;
void *__guard_dispatch_icall_fptr = (void *)__guard_check_icall_dummy;
__attribute__((used)) const IMAGE_LOAD_CONFIG_DIRECTORY64 _load_config_used = {
    .Size = sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64),
    .SecurityCookie = (ULONGLONG)&__security_cookie,
    .GuardCFCheckFunctionPointer = (ULONGLONG)&__guard_check_icall_fptr,
    .GuardCFDispatchFunctionPointer = (ULONGLONG)&__guard_dispatch_icall_fptr,
    .GuardCFFunctionTable = (ULONGLONG)&__guard_fids_table,
    .GuardCFFunctionCount = (ULONGLONG)&__guard_fids_count,
    .GuardFlags = 0x10500, /* CF_INSTRUMENTED | CF_FUNCTION_TABLE_PRESENT | CF_LONGJUMP_TABLE_PRESENT */
    .GuardAddressTakenIatEntryTable = (ULONGLONG)&__guard_iat_table,
    .GuardAddressTakenIatEntryCount = (ULONGLONG)&__guard_iat_count,
    .GuardLongJumpTargetTable = (ULONGLONG)&__guard_longjmp_table,
    .GuardLongJumpTargetCount = (ULONGLONG)&__guard_longjmp_count,
    .GuardEHContinuationTable = (ULONGLONG)&__guard_eh_cont_table,
    .GuardEHContinuationCount = (ULONGLONG)&__guard_eh_cont_count,
};
#else
extern void *__safe_se_handler_table;
extern char __safe_se_handler_count;
__attribute__((used)) const IMAGE_LOAD_CONFIG_DIRECTORY32 _load_config_used = {
    .Size = sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32),
    .SecurityCookie = (DWORD)&__security_cookie,
    .SEHandlerTable = (DWORD)&__safe_se_handler_table,
    .SEHandlerCount = (DWORD)&__safe_se_handler_count,
};
#endif

#ifndef _WIN64
/* A registered SafeSEH handler (x86 only), listed in the SEH table. */
EXCEPTION_DISPOSITION __cdecl filly_seh_handler(void *record, void *frame, void *context, void *dispatch)
{
    (void)record; (void)frame; (void)context; (void)dispatch;
    return ExceptionContinueSearch;
}
__asm__(".safeseh _filly_seh_handler");
#endif

/* --- Delay-load helper: never called for real ---------------------------- */
FARPROC WINAPI __delayLoadHelper2(const void *descriptor, FARPROC *slot) { (void)descriptor; return *slot; }

/* --- Exports --------------------------------------------------------------- */
int filly_version = 3;
static int (*volatile indirect)(int) = 0;

__declspec(noinline) int filly_add(int a, int b) { return a + b; }
__declspec(noinline) int filly_mul(int a, int b) { return a * b; }
__declspec(noinline) int filly_hidden(int a) { return a ^ 0x5a; }

int filly_work(int n)
{
    char buffer[64];
    int total = 0;
    for (int i = 0; i < n && i < 64; i++) {
        buffer[i] = (char)(i * 3);
        total += buffer[i];
    }
    indirect = filly_hidden;
    total += indirect(total);
    total += helper_named(total) + helper_ord(n);
    total += delay_one(total) + delay_two(n);
    total += (int)GetTickCount();
    Sleep(0);
    return total + filly_counter;
}

BOOL WINAPI filly_entry(HINSTANCE h, DWORD reason, LPVOID r)
{
    (void)h; (void)r;
    return reason != 0xFFFF && filly_work(4) != 0x7fffffff;
}

int filly_main(void)
{
    ExitProcess((UINT)filly_work(8));
}
