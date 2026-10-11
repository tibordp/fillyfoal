// Writes console-propstore.lnk with securifybv.ShellLink and
// securifybv.PropertyStore (see make-lnk.sh): a shell link to cmd.exe with a
// ConsoleDataBlock and a PropertyStoreDataBlock holding two storages
// (AppUserModel and Storage properties, keyed by ID).
// The libraries write the shell link, the extra data blocks and the
// serialized property store framing (sizes, "1SPS", FMTIDs, IDs,
// terminators); the TypedPropertyValue bodies are passed in as bytes, built
// here per MS-OLEPS 2.15.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PropertyStore;
using PropertyStore.Flags;
using PropertyStore.Structures;
using ShellLink;
using ShellLink.Flags;
using ShellLink.Structures;

static byte[] Pad4(byte[] b) => b.Concat(new byte[(4 - b.Length % 4) % 4]).ToArray();

// VT_LPWSTR: character count including the terminator, UTF-16LE, padding.
static byte[] Lpwstr(string s) =>
    Pad4(BitConverter.GetBytes((uint)(s.Length + 1)).Concat(Encoding.Unicode.GetBytes(s + "\0")).ToArray());

static TypedPropertyValue Typed(ushort vt, byte[] body) => new TypedPropertyValue((PropertyType)vt, body);

var appUserModel = new SerializedPropertyStorage
{
    FormatID = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"),
    PropertyStorage = new List<SerializedPropertyValue>
    {
        new IntegerName(5, Typed(0x1f, Lpwstr("Fillyfoal.Example"))),
        // VT_BOOL VARIANT_TRUE, padded to 4 bytes.
        new IntegerName(9, Typed(0x0b, new byte[] { 0xff, 0xff, 0, 0 })),
    },
};
var storage = new SerializedPropertyStorage
{
    FormatID = new Guid("B725F130-47EF-101A-A5F1-02608C9EEBAC"),
    PropertyStorage = new List<SerializedPropertyValue>
    {
        // System.Size, VT_UI8.
        new IntegerName(12, Typed(0x15, BitConverter.GetBytes(1234UL))),
        // System.DateModified, VT_FILETIME: 2024-01-02 03:04:05 UTC.
        new IntegerName(14, Typed(0x40, BitConverter.GetBytes(new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc).ToFileTimeUtc()))),
    },
};
// No storage keyed by name: securifybv.PropertyStore 0.1.0 writes the
// name's bytes wrongly (two characters, then zeros). The synthetic
// ms-propstore fixture covers named values.
var lnk = Shortcut.CreateShortcut(@"C:\Windows\System32\cmd.exe", "/k echo fillyfoal", @"C:\Windows\System32\cmd.exe", 0);
lnk.ExtraData.PropertyStoreDataBlock = new PropertyStoreDataBlock(
    new List<SerializedPropertyStorage> { appUserModel, storage });
lnk.ExtraData.ConsoleDataBlock = new ConsoleDataBlock
{
    FillAttributes = (FillAttributes)0x07,
    PopupFillAttributes = (FillAttributes)0xf5,
    ScreenBufferSizeX = 120,
    ScreenBufferSizeY = 9001,
    WindowSizeX = 120,
    WindowSizeY = 30,
    FontSize = 16 << 16,
    FontFamily = (FontFamily)0x30,
    FontPitch = (FontPitch)0x06,
    FontWeight = 400,
    FaceName = "Consolas",
    CursorSize = 25,
    QuickEdit = true,
    InsertMode = true,
    AutoPosition = true,
    HistoryBufferSize = 50,
    NumberOfHistoryBuffers = 4,
    ColorTable = Enumerable.Range(0, 16)
        .SelectMany(i => new byte[] { (byte)(i * 16), (byte)(255 - i * 16), (byte)(i * 8), 0 })
        .ToArray(),
};
lnk.WriteToFile(args[0]);
