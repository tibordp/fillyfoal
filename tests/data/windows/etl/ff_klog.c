// Starts a short kernel (SystemTraceProvider) session, triggers a process start, stops it.
// Usage: ff_klog.exe <kernel|system> <out.etl> <hex EnableFlags> <milliseconds>
//   kernel: the classic "NT Kernel Logger" session
//   system: a private session named "ff-syslog" with EVENT_TRACE_SYSTEM_LOGGER_MODE (Win8+)
// Must run elevated. Build (arm64): cl /nologo /W4 /O2 ff_klog.c advapi32.lib
#define INITGUID
#include <windows.h>
#include <evntrace.h>
#include <stdio.h>
#include <stdlib.h>

int wmain(int argc, wchar_t **argv)
{
    if (argc != 5) { fwprintf(stderr, L"usage: ff_klog <kernel|system> out.etl flags ms\n"); return 2; }
    BOOL sys = wcscmp(argv[1], L"system") == 0;
    const wchar_t *name = sys ? L"ff-syslog" : KERNEL_LOGGER_NAMEW;
    ULONG flags = wcstoul(argv[3], NULL, 16);
    DWORD ms = wcstoul(argv[4], NULL, 10);

    size_t sz = sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024 * sizeof(wchar_t);
    EVENT_TRACE_PROPERTIES *p = calloc(1, sz);
    p->Wnode.BufferSize = (ULONG)sz;
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1; // QPC
    if (!sys) p->Wnode.Guid = SystemTraceControlGuid;
    p->BufferSize = 8;           // KiB
    p->MinimumBuffers = 64;
    p->MaximumBuffers = 512;
    p->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL | (sys ? EVENT_TRACE_SYSTEM_LOGGER_MODE : 0);
    p->EnableFlags = flags;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    p->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(wchar_t);
    wcscpy_s((wchar_t *)((BYTE *)p + p->LogFileNameOffset), 1024, argv[2]);

    TRACEHANDLE h = 0;
    ULONG rc = StartTraceW(&h, name, p);
    if (rc != ERROR_SUCCESS) { fwprintf(stderr, L"StartTrace failed: %lu\n", rc); return 1; }

    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    wchar_t cmd[] = L"cmd.exe /c echo fillyfoal test";
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    Sleep(ms);

    rc = ControlTraceW(h, name, p, EVENT_TRACE_CONTROL_STOP);
    wprintf(L"stopped %s: rc=%lu events lost=%lu buffers written=%lu\n", name, rc, p->EventsLost, p->BuffersWritten);
    free(p);
    return rc == ERROR_SUCCESS ? 0 : 1;
}
