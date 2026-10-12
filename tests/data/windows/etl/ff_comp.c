// Records a short ETW session with EVENT_TRACE_COMPRESSED_MODE (0x04000000), i.e. the
// session itself writes compressed buffers (as opposed to compressing afterwards with xperf -merge).
// Providers: Microsoft-Windows-Kernel-Process (keyword 0x10 = process, level 4) and the
// fillyfoal-test TraceLogging provider. Triggers two "cmd /c echo" process starts and runs
// fillyfoal_tlg.exe (path given on the command line).
// Usage: ff_comp.exe <out.etl> <path\to\fillyfoal_tlg.exe>
// Must run elevated. Build (arm64): cl /nologo /W4 /O2 ff_comp.c advapi32.lib
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
#include <stdlib.h>

static const GUID KernelProcess = // {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
    {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
static const GUID FillyfoalTest = // {a946bbbd-88e8-5895-7beb-4d343c1d945f}
    {0xa946bbbd, 0x88e8, 0x5895, {0x7b, 0xeb, 0x4d, 0x34, 0x3c, 0x1d, 0x94, 0x5f}};

static void run(wchar_t *cmd)
{
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    } else {
        fwprintf(stderr, L"CreateProcess failed: %lu\n", GetLastError());
    }
}

int wmain(int argc, wchar_t **argv)
{
    if (argc != 3) { fwprintf(stderr, L"usage: ff_comp out.etl fillyfoal_tlg.exe\n"); return 2; }
    const wchar_t *name = L"ff-compressed";
    size_t sz = sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024 * sizeof(wchar_t);
    EVENT_TRACE_PROPERTIES *p = calloc(1, sz);
    p->Wnode.BufferSize = (ULONG)sz;
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1; // QPC
    p->BufferSize = 64;         // KiB
    p->MinimumBuffers = 4;
    p->MaximumBuffers = 16;
    p->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_COMPRESSED_MODE;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    p->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(wchar_t);
    wcscpy_s((wchar_t *)((BYTE *)p + p->LogFileNameOffset), 1024, argv[1]);

    TRACEHANDLE h = 0;
    ULONG rc = StartTraceW(&h, name, p);
    if (rc == ERROR_ALREADY_EXISTS) {
        ControlTraceW(0, name, p, EVENT_TRACE_CONTROL_STOP);
        p->Wnode.BufferSize = (ULONG)sz; p->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_COMPRESSED_MODE;
        rc = StartTraceW(&h, name, p);
    }
    if (rc != ERROR_SUCCESS) { fwprintf(stderr, L"StartTrace failed: %lu\n", rc); return 1; }
    rc = EnableTraceEx2(h, &KernelProcess, EVENT_CONTROL_CODE_ENABLE_PROVIDER, 4, 0x10, 0, 0, NULL);
    if (rc) fwprintf(stderr, L"enable Kernel-Process: %lu\n", rc);
    rc = EnableTraceEx2(h, &FillyfoalTest, EVENT_CONTROL_CODE_ENABLE_PROVIDER, 5, ~0ULL, 0, 0, NULL);
    if (rc) fwprintf(stderr, L"enable fillyfoal-test: %lu\n", rc);

    wchar_t c1[] = L"cmd.exe /c echo fillyfoal test 1";
    wchar_t c2[] = L"cmd.exe /c echo fillyfoal test 2";
    wchar_t c3[1100];
    swprintf_s(c3, 1100, L"\"%s\"", argv[2]);
    run(c1);
    run(c2);
    run(c3);
    Sleep(300);

    rc = ControlTraceW(h, name, p, EVENT_TRACE_CONTROL_STOP);
    wprintf(L"stopped %s: rc=%lu mode=%#lx events lost=%lu buffers written=%lu\n",
            name, rc, p->LogFileMode, p->EventsLost, p->BuffersWritten);
    free(p);
    return rc == ERROR_SUCCESS ? 0 : 1;
}
