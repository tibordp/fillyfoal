// fillyfoal test TraceLogging provider.
// Logs a handful of self-describing (TraceLogging) events with assorted field types.
// Provider name "fillyfoal-test"; GUID is the standard EventSource-style name hash of
// "fillyfoal-test": {a946bbbd-88e8-5895-7beb-4d343c1d945f}, so "*fillyfoal-test" works in tools.
// Build (arm64): cl /nologo /W4 /O2 fillyfoal_tlg.c advapi32.lib
#include <windows.h>
#include <winmeta.h>
#include <TraceLoggingProvider.h>
#include <stdio.h>

#define FF_GUID (0xa946bbbd, 0x88e8, 0x5895, 0x7b, 0xeb, 0x4d, 0x34, 0x3c, 0x1d, 0x94, 0x5f)

TRACELOGGING_DEFINE_PROVIDER(g_ff, "fillyfoal-test", FF_GUID);

int main(void)
{
    static const GUID sample_guid =
        {0x01234567, 0x89ab, 0xcdef, {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}};
    static const BYTE blob[16] = {0x66, 0x69, 0x6c, 0x6c, 0x79, 0x66, 0x6f, 0x61,
                                  0x6c, 0x00, 0x01, 0x02, 0xfe, 0xff, 0x7f, 0x80};
    // 2024-01-02 03:04:05 UTC
    SYSTEMTIME st = {2024, 1, 2, 2, 3, 4, 5, 0};
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);
    INT32 arr[4] = {1, -2, 3, -4};

    TraceLoggingRegister(g_ff);
    for (int i = 0; i < 3; i++) {
        TraceLoggingWrite(g_ff, "FillyfoalScalars",
            TraceLoggingLevel(WINEVENT_LEVEL_INFO),
            TraceLoggingKeyword(0x1),
            TraceLoggingInt32(i, "Index"),
            TraceLoggingInt32(-123456, "Int32"),
            TraceLoggingUInt64(0x0123456789abcdefULL, "UInt64"),
            TraceLoggingHexUInt32(0xdeadbeef, "Hex32"),
            TraceLoggingInt8(-8, "Int8"),
            TraceLoggingUInt16(65535, "UInt16"),
            TraceLoggingFloat64(3.25, "Double"),
            TraceLoggingBoolean(TRUE, "Bool"));
        TraceLoggingWrite(g_ff, "FillyfoalStrings",
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
            TraceLoggingKeyword(0x2),
            TraceLoggingString("fillyfoal test", "Ansi"),
            TraceLoggingWideString(L"fillyfoal test \x00e9\x4e2d", "Utf16"),
            TraceLoggingCountedString("counted!", 8, "Counted"));
        TraceLoggingWrite(g_ff, "FillyfoalComplex",
            TraceLoggingLevel(WINEVENT_LEVEL_WARNING),
            TraceLoggingKeyword(0x4),
            TraceLoggingGuid(sample_guid, "Guid"),
            TraceLoggingFileTime(ft, "FileTime"),
            TraceLoggingSystemTime(st, "SystemTime"),
            TraceLoggingBinary(blob, sizeof(blob), "Binary"),
            TraceLoggingInt32FixedArray(arr, 4, "FixedArray"),
            TraceLoggingInt32Array(arr, 3, "VarArray"),
            TraceLoggingStruct(2, "Nested"),
                TraceLoggingInt32(42, "Answer"),
                TraceLoggingString("inner", "Name"));
        Sleep(50);
    }
    TraceLoggingUnregister(g_ff);
    printf("fillyfoal-test: logged 9 events\n");
    return 0;
}
