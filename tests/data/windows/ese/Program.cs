// fillyfoal ESE fixture generator.
//
// Usage (one database per process, because JET_paramDatabasePageSize is process-global):
//   EseFixtures plain <pageSizeBytes> <workDir> <outFile> [dbExtensionPages]
//   EseFixtures compressed <pageSizeBytes> <workDir> <outFile> [dbExtensionPages]
//
// Settings: JET_paramRecovery = "Off" (no transaction logs / checkpoint written at all),
// JET_paramCircularLog = 1, JET_paramMaxTemporaryTables = 0 (no tmp.edb), all engine paths
// (system / temp / log) point at <workDir>. The database is closed, detached and the
// instance terminated with JET_bitTermComplete (clean shutdown); then only the .edb is
// copied to <outFile>.
//
// All content is synthetic and deterministic (fixed seed LCG, fixed base date, GUIDs derived
// from the row number).

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

static unsafe class Program
{
    // ---------------------------------------------------------------- esent.dll
    const string Esent = "esent.dll";

    [StructLayout(LayoutKind.Sequential)]
    struct JET_COLUMNDEF
    {
        public uint cbStruct;
        public uint columnid;
        public uint coltyp;
        public ushort wCountry;
        public ushort langid;
        public ushort cp;
        public ushort wCollate;
        public uint cbMax;
        public uint grbit;
    }

    [DllImport(Esent, CharSet = CharSet.Unicode)] static extern int JetSetSystemParameterW(ref IntPtr instance, IntPtr sesid, uint paramid, IntPtr lParam, string szParam);
    [DllImport(Esent, CharSet = CharSet.Unicode)] static extern int JetCreateInstance2W(out IntPtr instance, string name, string displayName, uint grbit);
    [DllImport(Esent)] static extern int JetInit(ref IntPtr instance);
    [DllImport(Esent, CharSet = CharSet.Unicode)] static extern int JetBeginSessionW(IntPtr instance, out IntPtr sesid, string user, string password);
    [DllImport(Esent, CharSet = CharSet.Unicode)] static extern int JetCreateDatabase2W(IntPtr sesid, string file, uint cpgMax, out uint dbid, uint grbit);
    [DllImport(Esent, CharSet = CharSet.Unicode)] static extern int JetCreateTableW(IntPtr sesid, uint dbid, string name, uint pages, uint density, out IntPtr tableid);
    [DllImport(Esent, CharSet = CharSet.Unicode)] static extern int JetAddColumnW(IntPtr sesid, IntPtr tableid, string name, ref JET_COLUMNDEF def, IntPtr pvDefault, uint cbDefault, out uint columnid);
    [DllImport(Esent, CharSet = CharSet.Unicode)] static extern int JetCreateIndexW(IntPtr sesid, IntPtr tableid, string name, uint grbit, string key, uint cbKey, uint density);
    [DllImport(Esent)] static extern int JetBeginTransaction(IntPtr sesid);
    [DllImport(Esent)] static extern int JetCommitTransaction(IntPtr sesid, uint grbit);
    [DllImport(Esent)] static extern int JetPrepareUpdate(IntPtr sesid, IntPtr tableid, uint prep);
    [DllImport(Esent)] static extern int JetSetColumn(IntPtr sesid, IntPtr tableid, uint columnid, byte* data, uint cb, uint grbit, IntPtr setinfo);
    [DllImport(Esent)] static extern int JetUpdate(IntPtr sesid, IntPtr tableid, IntPtr bookmark, uint cbBookmark, IntPtr cbActual);
    [DllImport(Esent)] static extern int JetCloseTable(IntPtr sesid, IntPtr tableid);
    [DllImport(Esent)] static extern int JetResizeDatabase(IntPtr sesid, uint dbid, uint cpgTarget, out uint cpgActual, uint grbit);
    [DllImport(Esent)] static extern int JetCloseDatabase(IntPtr sesid, uint dbid, uint grbit);
    [DllImport(Esent, CharSet = CharSet.Unicode)] static extern int JetDetachDatabaseW(IntPtr sesid, string file);
    [DllImport(Esent)] static extern int JetEndSession(IntPtr sesid, uint grbit);
    [DllImport(Esent)] static extern int JetTerm2(IntPtr instance, uint grbit);

    const uint JET_paramSystemPath = 0, JET_paramTempPath = 1, JET_paramLogFilePath = 2, JET_paramBaseName = 3,
        JET_paramMaxTemporaryTables = 10, JET_paramDbExtensionSize = 18, JET_paramEnableShrinkDatabase = 184, JET_paramCircularLog = 17, JET_paramRecovery = 34,
        JET_paramNoInformationEvent = 50, JET_paramDatabasePageSize = 64, JET_paramCreatePathIfNotExist = 100,
        JET_paramEnableAdvanced = 130;
    const uint JET_coltypLong = 4, JET_coltypDateTime = 8, JET_coltypText = 10, JET_coltypLongBinary = 11,
        JET_coltypLongText = 12, JET_coltypGUID = 16;
    const uint JET_bitColumnFixed = 0x1, JET_bitColumnTagged = 0x2, JET_bitColumnNotNULL = 0x4,
        JET_bitColumnCompressed = 0x80000;
    const uint JET_bitIndexPrimary = 0x2, JET_bitIndexUnique = 0x1;
    const uint JET_bitDbOverwriteExisting = 0x200, JET_bitDbRecoveryOff = 0x8;
    const uint JET_bitTermComplete = 0x1;
    const uint JET_prepInsert = 0;
    const uint JET_bitSetCompressed = 0x20000;

    static void Check(int err, string what)
    {
        if (err < 0) throw new Exception($"{what} failed: JET error {err}");
        if (err > 0) Console.WriteLine($"  warning {err} from {what}");
    }

    // ---------------------------------------------------------------- deterministic content
    static uint lcgState;
    static uint Next() { lcgState = lcgState * 1664525u + 1013904223u; return lcgState; }

    static readonly string[] Words = (
        "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore " +
        "et dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi " +
        "aliquip ex ea commodo consequat duis aute irure in reprehenderit voluptate velit esse cillum " +
        "fugiat nulla pariatur excepteur sint occaecat cupidatat non proident sunt culpa qui officia " +
        "deserunt mollit anim id est laborum fillyfoal test").Split(' ');

    // Pseudo-random word salad (seeded) – not very compressible beyond the word level.
    static string Lorem(int chars, uint seed)
    {
        lcgState = seed;
        var sb = new StringBuilder(chars + 32);
        while (sb.Length < chars)
        {
            uint r = Next();
            sb.Append(Words[(r >> 8) % (uint)Words.Length]);
            if (((r >> 20) & 15) == 0) sb.Append(' ').Append((r >> 4) % 100000);
            sb.Append(((r >> 24) & 31) == 0 ? ". " : " ");
        }
        return sb.ToString(0, chars);
    }

    static byte[] RandomBytes(int n, uint seed)
    {
        lcgState = seed;
        var b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte)(Next() >> 24);
        return b;
    }

    static readonly DateTime BaseDate = new DateTime(2024, 1, 1, 12, 0, 0, DateTimeKind.Utc);

    static Guid RowGuid(int row)
    {
        // fixed GUIDs: 0f111f0a-1e57-4000-8000-0000000000NN style
        var b = new byte[16];
        BitConverter.GetBytes(0x0f111f0au).CopyTo(b, 0);
        BitConverter.GetBytes((ushort)0x1e57).CopyTo(b, 4);
        BitConverter.GetBytes((ushort)0x4000).CopyTo(b, 6);
        b[8] = 0x80; b[9] = 0x00;
        BitConverter.GetBytes((long)row).CopyTo(b, 8 + 0); // overwrite low part with row number
        b[8] = 0x80; // keep RFC 4122 variant bits
        return new Guid(b);
    }

    // ---------------------------------------------------------------- helpers
    static IntPtr ses;
    static IntPtr tbl;

    static uint AddColumn(string name, uint coltyp, uint grbit, ushort cp = 0, uint cbMax = 0)
    {
        var def = new JET_COLUMNDEF
        {
            cbStruct = (uint)sizeof(JET_COLUMNDEF), coltyp = coltyp, cp = cp, cbMax = cbMax, grbit = grbit,
        };
        Check(JetAddColumnW(ses, tbl, name, ref def, IntPtr.Zero, 0, out uint id), "JetAddColumn " + name);
        return id;
    }

    static void Set(uint col, byte[] data, uint grbit = 0)
    {
        fixed (byte* p = data) Check(JetSetColumn(ses, tbl, col, p, (uint)data.Length, grbit, IntPtr.Zero), "JetSetColumn");
    }
    static void SetInt(uint col, int v) => Set(col, BitConverter.GetBytes(v));
    static void SetDate(uint col, DateTime d) => Set(col, BitConverter.GetBytes(d.ToOADate()));
    static void SetGuid(uint col, Guid g) => Set(col, g.ToByteArray());
    static void SetAscii(uint col, string s, uint grbit = 0) => Set(col, Encoding.ASCII.GetBytes(s), grbit);
    static void SetUnicode(uint col, string s, uint grbit = 0) => Set(col, Encoding.Unicode.GetBytes(s), grbit);

    static void CreatePrimaryIndex()
    {
        string key = "+Id\0\0";
        Check(JetCreateIndexW(ses, tbl, "PK_Id", JET_bitIndexPrimary | JET_bitIndexUnique, key, (uint)(key.Length * 2), 100), "JetCreateIndex");
    }

    // ---------------------------------------------------------------- tables
    static void BuildPlain(uint dbid)
    {
        Check(JetCreateTableW(ses, dbid, "fillyfoal_test", 0, 100, out tbl), "JetCreateTable");
        uint cId = AddColumn("Id", JET_coltypLong, JET_bitColumnFixed | JET_bitColumnNotNULL);
        uint cName = AddColumn("Name", JET_coltypText, 0, 1252, 255);
        uint cNotes = AddColumn("Notes", JET_coltypLongText, JET_bitColumnTagged, 1200);
        uint cBlob = AddColumn("Payload", JET_coltypLongBinary, JET_bitColumnTagged);
        uint cWhen = AddColumn("Created", JET_coltypDateTime, JET_bitColumnFixed);
        uint cUid = AddColumn("Uid", JET_coltypGUID, JET_bitColumnFixed);
        CreatePrimaryIndex();

        for (int i = 1; i <= 60; i++)
        {
            Check(JetBeginTransaction(ses), "JetBeginTransaction");
            Check(JetPrepareUpdate(ses, tbl, JET_prepInsert), "JetPrepareUpdate");
            SetInt(cId, i);
            SetAscii(cName, $"fillyfoal test row {i:D2}");
            SetDate(cWhen, BaseDate.AddDays(i).AddMinutes(i * 7));
            SetGuid(cUid, RowGuid(i));
            if (i % 20 == 0)
            {
                // larger than any page size: goes into the long-value tree
                SetUnicode(cNotes, Lorem(20 * 1024 + i * 10, 0xF111u + (uint)i)); // ~40-41 KiB UTF-16
                Set(cBlob, RandomBytes(40 * 1024 + i, 0xB10Bu + (uint)i));        // ~40 KiB random
            }
            else
            {
                SetUnicode(cNotes, $"note {i}: " + Lorem(20 + (i * 13) % 120, 0x1000u + (uint)i));
                if (i % 3 != 0) Set(cBlob, RandomBytes(8 + (i * 7) % 90, 0x2000u + (uint)i));
            }
            Check(JetUpdate(ses, tbl, IntPtr.Zero, 0, IntPtr.Zero), "JetUpdate");
            Check(JetCommitTransaction(ses, 0), "JetCommitTransaction");
        }
        Check(JetCloseTable(ses, tbl), "JetCloseTable");
    }

    static void BuildCompressed(uint dbid)
    {
        Check(JetCreateTableW(ses, dbid, "fillyfoal_compressed", 0, 100, out tbl), "JetCreateTable");
        uint cId = AddColumn("Id", JET_coltypLong, JET_bitColumnFixed | JET_bitColumnNotNULL);
        uint cKind = AddColumn("Kind", JET_coltypText, 0, 1252, 64);
        // tagged long compressed columns (ESE only allows compression on LongText / LongBinary,
        // JET_errColumnCannotBeCompressed otherwise)
        uint cLtA = AddColumn("LongAscii", JET_coltypLongText, JET_bitColumnTagged | JET_bitColumnCompressed, 1252);
        uint cLtU = AddColumn("LongUnicode", JET_coltypLongText, JET_bitColumnTagged | JET_bitColumnCompressed, 1200);
        uint cLb = AddColumn("LongBinary", JET_coltypLongBinary, JET_bitColumnTagged | JET_bitColumnCompressed);
        CreatePrimaryIndex();

        string rep = "fillyfoal test, lorem ipsum dolor sit amet 0123456789. ";
        for (int i = 1; i <= 30; i++)
        {
            Check(JetBeginTransaction(ses), "JetBeginTransaction");
            Check(JetPrepareUpdate(ses, tbl, JET_prepInsert), "JetPrepareUpdate");
            SetInt(cId, i);
            uint g = JET_bitSetCompressed;
            if (i <= 10)
            {
                // 7-bit ASCII candidates: plain ASCII in cp1252 columns, below the Xpress threshold
                SetAscii(cKind, "7bit-ascii");
                SetAscii(cLtA, $"row {i} " + Lorem(200 + i * 40, 0x3100u + (uint)i), g);
            }
            else if (i <= 20)
            {
                // 7-bit Unicode candidates: UTF-16LE text with only ASCII characters
                SetAscii(cKind, "7bit-unicode");
                SetUnicode(cLtU, $"row {i} " + Lorem(150 + (i - 10) * 30, 0x4100u + (uint)i), g);
            }
            else
            {
                // Xpress candidates: several KiB of highly repetitive text / bytes
                SetAscii(cKind, "xpress");
                var sb = new StringBuilder();
                int n = 2 + (i - 20); // 3..12 KiB-ish
                while (sb.Length < n * 1024) sb.Append(rep).Append(i).Append(' ');
                SetAscii(cLtA, sb.ToString(), g);
                SetUnicode(cLtU, sb.ToString(), g);
                var bytes = new byte[n * 1024];
                for (int k = 0; k < bytes.Length; k++) bytes[k] = (byte)((k % 64) < 32 ? k % 16 : 0xAA);
                Set(cLb, bytes, g);
            }
            Check(JetUpdate(ses, tbl, IntPtr.Zero, 0, IntPtr.Zero), "JetUpdate");
            Check(JetCommitTransaction(ses, 0), "JetCommitTransaction");
        }
        Check(JetCloseTable(ses, tbl), "JetCloseTable");
    }

    // ---------------------------------------------------------------- main
    static int Main(string[] args)
    {
        if (args.Length < 4 || args.Length > 5) { Console.Error.WriteLine("usage: plain|compressed <pageSize> <workDir> <outFile> [dbExtensionPages]"); return 2; }
        // JET_paramDbExtensionSize only influences how much the file grows per extension; the
        // values used in build.ps1 were picked empirically to give the smallest files.
        int extPages = args.Length == 5 ? int.Parse(args[4]) : 16;
        string mode = args[0];
        int pageSize = int.Parse(args[1]);
        string work = Path.GetFullPath(args[2]);
        string outFile = Path.GetFullPath(args[3]);
        if (Directory.Exists(work)) Directory.Delete(work, true);
        Directory.CreateDirectory(work);
        string dir = work.EndsWith("\\") ? work : work + "\\";
        string dbPath = Path.Combine(work, Path.GetFileName(outFile));

        IntPtr none = IntPtr.Zero;
        Check(JetSetSystemParameterW(ref none, IntPtr.Zero, JET_paramDatabasePageSize, (IntPtr)pageSize, null), "DatabasePageSize");
        Check(JetSetSystemParameterW(ref none, IntPtr.Zero, JET_paramEnableAdvanced, (IntPtr)1, null), "EnableAdvanced");

        Check(JetCreateInstance2W(out IntPtr inst, "fillyfoal", "fillyfoal", 0), "JetCreateInstance2");
        Check(JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramSystemPath, IntPtr.Zero, dir), "SystemPath");
        Check(JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramTempPath, IntPtr.Zero, dir), "TempPath");
        Check(JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramLogFilePath, IntPtr.Zero, dir), "LogFilePath");
        Check(JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramBaseName, IntPtr.Zero, "edb"), "BaseName");
        Check(JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramRecovery, IntPtr.Zero, "Off"), "Recovery");
        Check(JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramCircularLog, (IntPtr)1, null), "CircularLog");
        Check(JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramMaxTemporaryTables, IntPtr.Zero, null), "MaxTemporaryTables");
        Check(JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramNoInformationEvent, (IntPtr)1, null), "NoInformationEvent");
        Check(JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramCreatePathIfNotExist, (IntPtr)1, null), "CreatePathIfNotExist");
        Check(JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramDbExtensionSize, (IntPtr)extPages, null), "DbExtensionSize");
        Check(JetSetSystemParameterW(ref inst, IntPtr.Zero, JET_paramEnableShrinkDatabase, (IntPtr)1, null), "EnableShrinkDatabase");
        Check(JetInit(ref inst), "JetInit");

        Check(JetBeginSessionW(inst, out ses, null, null), "JetBeginSession");
        Check(JetCreateDatabase2W(ses, dbPath, 0, out uint dbid, JET_bitDbOverwriteExisting), "JetCreateDatabase2");
        if (mode == "plain") BuildPlain(dbid);
        else if (mode == "compressed") BuildCompressed(dbid);
        else throw new ArgumentException(mode);
        // shrink the file from its default initial size down to what is actually used
        Check(JetResizeDatabase(ses, dbid, 1, out uint cpgActual, 0x2 /* JET_bitResizeDatabaseOnlyShrink */), "JetResizeDatabase");
        Console.WriteLine($"  resized to {cpgActual} pages");
        Check(JetCloseDatabase(ses, dbid, 0), "JetCloseDatabase");
        Check(JetDetachDatabaseW(ses, dbPath), "JetDetachDatabase");
        Check(JetEndSession(ses, 0), "JetEndSession");
        Check(JetTerm2(inst, JET_bitTermComplete), "JetTerm2");

        Console.WriteLine("files left in work dir:");
        foreach (var f in Directory.GetFiles(work)) Console.WriteLine($"  {Path.GetFileName(f)}  {new FileInfo(f).Length}");
        Directory.CreateDirectory(Path.GetDirectoryName(outFile));
        File.Copy(dbPath, outFile, true);
        Console.WriteLine($"wrote {outFile} ({new FileInfo(outFile).Length} bytes)");
        return 0;
    }
}
