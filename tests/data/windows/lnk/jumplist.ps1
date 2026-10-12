# Make Windows write AutomaticDestinations / CustomDestinations jump-list files that contain only
# fillyfoal paths, by running under a dedicated AppUserModelID ("fillyfoal.test"):
#  - SHAddToRecentDocs(SHARD_PATHW) for C:\fillyfoal\note.txt and C:\fillyfoal\notes
#    -> %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\<hash>.automaticDestinations-ms
#       (and Recent\note.txt.lnk / Recent\notes.lnk)
#  - ICustomDestinationList with a custom category "fillyfoal" and one user task
#    -> %APPDATA%\Microsoft\Windows\Recent\CustomDestinations\<hash>.customDestinations-ms
# Run in its own process (it changes the process AppUserModelID):
#   powershell -NoProfile -STA -ExecutionPolicy Bypass -File jumplist.ps1
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class FfJump {
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern int SetCurrentProcessExplicitAppUserModelID(string id);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern void SHAddToRecentDocs(uint flags, string path);

    [ComImport, Guid("6332DEBF-87B5-4670-90C0-5E57B408A49E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface ICustomDestinationList {
        void SetAppID([MarshalAs(UnmanagedType.LPWStr)] string id);
        void BeginList(out uint maxSlots, ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object removed);
        void AppendCategory([MarshalAs(UnmanagedType.LPWStr)] string category, [MarshalAs(UnmanagedType.Interface)] IObjectArray items);
        void AppendKnownCategory(int category);
        void AddUserTasks([MarshalAs(UnmanagedType.Interface)] IObjectArray items);
        void CommitList();
        void GetRemovedDestinations(ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object removed);
        void DeleteList([MarshalAs(UnmanagedType.LPWStr)] string id);
        void AbortList();
    }
    [ComImport, Guid("92CA9DCD-5622-4BBA-A805-5E9F541BD8C9"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IObjectArray {
        void GetCount(out uint n);
        void GetAt(uint i, ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object o);
    }
    [ComImport, Guid("5632B1A4-E38A-400A-928A-D4CD63230295"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IObjectCollection {
        void GetCount(out uint n);
        void GetAt(uint i, ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object o);
        void AddObject([MarshalAs(UnmanagedType.Interface)] object o);
        void AddFromArray(IObjectArray a);
        void RemoveObjectAt(uint i);
        void Clear();
    }
    [ComImport, Guid("000214F9-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IShellLinkW {
        void GetPath(IntPtr a, int b, IntPtr c, uint d);
        void GetIDList(out IntPtr p);
        void SetIDList(IntPtr p);
        void GetDescription(IntPtr a, int b);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string s);
        void GetWorkingDirectory(IntPtr a, int b);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string s);
        void GetArguments(IntPtr a, int b);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string s);
        void GetHotkey(out short h);
        void SetHotkey(short h);
        void GetShowCmd(out int c);
        void SetShowCmd(int c);
        void GetIconLocation(IntPtr a, int b, out int c);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string s, int i);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string s, uint r);
        void Resolve(IntPtr h, uint f);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string s);
    }
    [ComImport, Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IPropertyStore {
        void GetCount(out uint n);
        void GetAt(uint i, out PROPERTYKEY k);
        void GetValue(ref PROPERTYKEY k, IntPtr v);
        void SetValue(ref PROPERTYKEY k, ref PROPVARIANT v);
        void Commit();
    }
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct PROPERTYKEY { public Guid fmtid; public uint pid; }
    [StructLayout(LayoutKind.Sequential)]
    struct PROPVARIANT { public ushort vt; public ushort r1, r2, r3; public IntPtr p; public IntPtr p2; }

    static object Link(string path, string args, string title) {
        var l = (IShellLinkW)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("00021401-0000-0000-C000-000000000046")));
        l.SetPath(path);
        if (args != null) l.SetArguments(args);
        l.SetDescription(title);
        var ps = (IPropertyStore)l;
        var key = new PROPERTYKEY { fmtid = new Guid("F29F85E0-4FF9-1068-AB91-08002B27B3D9"), pid = 2 }; // PKEY_Title
        var pv = new PROPVARIANT { vt = 31 /* VT_LPWSTR */, p = Marshal.StringToCoTaskMemUni(title) };
        ps.SetValue(ref key, ref pv);
        ps.Commit();
        return l;
    }

    public static void Run(string appId) {
        SetCurrentProcessExplicitAppUserModelID(appId);
        SHAddToRecentDocs(3 /* SHARD_PATHW */, @"C:\fillyfoal\note.txt");
        SHAddToRecentDocs(3, @"C:\fillyfoal\notes");

        var cdl = (ICustomDestinationList)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("77F10CF0-3DB5-4966-B520-B7C54FD35ED6")));
        cdl.SetAppID(appId);
        uint slots; object removed; var iidOA = typeof(IObjectArray).GUID;
        cdl.BeginList(out slots, ref iidOA, out removed);
        var cat = (IObjectCollection)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("2D3468C1-36A7-43B6-AC24-D3F02FD9607A")));
        cat.AddObject(Link(@"C:\Windows\System32\notepad.exe", @"C:\fillyfoal\note.txt", "fillyfoal note"));
        cat.AddObject(Link(@"C:\Windows\explorer.exe", @"C:\fillyfoal\notes", "fillyfoal notes folder"));
        cdl.AppendCategory("fillyfoal", (IObjectArray)cat);
        var tasks = (IObjectCollection)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("2D3468C1-36A7-43B6-AC24-D3F02FD9607A")));
        tasks.AddObject(Link(@"C:\Windows\System32\cmd.exe", "/c echo fillyfoal test", "fillyfoal task"));
        cdl.AddUserTasks((IObjectArray)tasks);
        cdl.AppendKnownCategory(2 /* KDC_RECENT */);
        cdl.CommitList();
    }
}
'@
[FfJump]::Run('fillyfoal.test')
Start-Sleep -Seconds 3
'done'
