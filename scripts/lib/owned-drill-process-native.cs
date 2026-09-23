using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Foliora.Drill
{
    internal sealed class KernelHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public KernelHandle() : base(true) { }
        internal void Initialize(IntPtr value) => SetHandle(value);
        protected override bool ReleaseHandle() => OwnedProcessNative.CloseHandle(handle);
    }

    internal static class OwnedProcessNative
    {
        internal static Win32Exception Error(string operation)
        {
            int code = Marshal.GetLastWin32Error();
            return new Win32Exception(code, operation + " failed (Win32 " + code + ").");
        }
        internal static void Check(bool success, string operation) { if (!success) throw Error(operation); }

        internal static bool Wait(KernelHandle process, int milliseconds)
        {
            uint result = WaitForSingleObject(process, (uint)milliseconds);
            if (result == 0) return true;
            if (result == 258) return false; // WAIT_TIMEOUT
            throw Error("WaitForSingleObject");
        }

        internal static KernelHandle CreateKillOnCloseJob()
        {
            var job = CreateJobObjectW(IntPtr.Zero, null); // Unnamed, non-inheritable handle.
            if (job.IsInvalid) { var error = Error("CreateJobObjectW"); job.Dispose(); throw error; }
            try
            {
                var limits = new ExtendedLimits();
                limits.BasicLimitInformation.LimitFlags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()),
                    "SetInformationJobObject");
                return job;
            }
            catch { job.Dispose(); throw; }
        }

        internal static int CreateSuspended(string executable, StringBuilder commandLine, string directory,
            string stdoutPath, string stderrPath, KernelHandle job, KernelHandle process, KernelHandle thread)
        {
            using var input = Open("NUL", 0x80000000, 3); // GENERIC_READ, OPEN_EXISTING
            using var output = Open(stdoutPath, 0x40000000, 2); // GENERIC_WRITE, CREATE_ALWAYS
            using var error = Open(stderrPath, 0x40000000, 2);
            IntPtr size = IntPtr.Zero, attributes = IntPtr.Zero, handles = IntPtr.Zero, jobs = IntPtr.Zero;
            bool initialized = false;
            try
            {
                // The sizing call intentionally fails with ERROR_INSUFFICIENT_BUFFER.
                bool sized = InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
                if (sized || Marshal.GetLastWin32Error() != 122 || size == IntPtr.Zero)
                    throw Error("InitializeProcThreadAttributeList size");
                attributes = Marshal.AllocHGlobal(size);
                Check(InitializeProcThreadAttributeList(attributes, 2, 0, ref size),
                    "InitializeProcThreadAttributeList");
                initialized = true;
                handles = Marshal.AllocHGlobal(3 * IntPtr.Size);
                Marshal.WriteIntPtr(handles, 0, input.DangerousGetHandle());
                Marshal.WriteIntPtr(handles, IntPtr.Size, output.DangerousGetHandle());
                Marshal.WriteIntPtr(handles, 2 * IntPtr.Size, error.DangerousGetHandle());
                Check(UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x20002, handles,
                    (IntPtr)(3 * IntPtr.Size), IntPtr.Zero, IntPtr.Zero), "UpdateProcThreadAttribute handle list");
                // Windows 10 JOB_LIST associates the job during creation, closing the suspended-orphan
                // window if the host dies. This attribute assigns ownership; it does not inherit the job handle.
                jobs = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(jobs, job.DangerousGetHandle());
                Check(UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x2000D, jobs,
                    (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero), "UpdateProcThreadAttribute job list");
                var startup = new StartupInfoEx();
                startup.StartupInfo.Size = (uint)Marshal.SizeOf<StartupInfoEx>();
                startup.StartupInfo.Flags = 0x101; // STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
                startup.StartupInfo.StandardInput = input.DangerousGetHandle();
                startup.StartupInfo.StandardOutput = output.DangerousGetHandle();
                startup.StartupInfo.StandardError = error.DangerousGetHandle();
                startup.AttributeList = attributes;
                // CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED; SW_HIDE = 0.
                Check(CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, true,
                    0x08080004, IntPtr.Zero, directory, ref startup, out ProcessInformation created),
                    "CreateProcessW");
                process.Initialize(created.Process);
                thread.Initialize(created.Thread);
                return unchecked((int)created.ProcessId);
            }
            finally
            {
                if (initialized) DeleteProcThreadAttributeList(attributes);
                if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
                if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
                if (jobs != IntPtr.Zero) Marshal.FreeHGlobal(jobs);
                // Keep handles alive through CreateProcess and destruction of the attribute list.
                GC.KeepAlive(input); GC.KeepAlive(output); GC.KeepAlive(error); GC.KeepAlive(job);
            }
        }

        private static KernelHandle Open(string path, uint access, uint disposition)
        {
            var security = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Inherit = 1 };
            var handle = CreateFileW(path, access, 3, ref security, disposition, 0x80, IntPtr.Zero);
            if (handle.IsInvalid) { var error = Error("CreateFileW"); handle.Dispose(); throw error; }
            return handle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes { internal int Length; internal IntPtr Descriptor; internal int Inherit; }
        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfo
        {
            internal uint Size;
            internal IntPtr Reserved, Desktop, Title;
            internal uint X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
            internal ushort ShowWindow, ReservedSize;
            internal IntPtr ReservedBytes, StandardInput, StandardOutput, StandardError;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfoEx { internal StartupInfo StartupInfo; internal IntPtr AttributeList; }
        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation { internal IntPtr Process, Thread; internal uint ProcessId, ThreadId; }
        [StructLayout(LayoutKind.Sequential)]
        private struct BasicLimits
        {
            internal long ProcessTime, JobTime;
            internal uint LimitFlags;
            internal UIntPtr MinimumWorkingSet, MaximumWorkingSet;
            internal uint ActiveProcessLimit;
            internal UIntPtr Affinity;
            internal uint PriorityClass, SchedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters { internal ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
        [StructLayout(LayoutKind.Sequential)]
        private struct ExtendedLimits
        {
            internal BasicLimits BasicLimitInformation;
            internal IoCounters IoInfo;
            internal UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct BasicAccounting
        {
            internal long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
            internal uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern KernelHandle CreateJobObjectW(IntPtr security, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(KernelHandle job, int kind, ref ExtendedLimits limits, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateJobObject(KernelHandle job, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryInformationJobObject(KernelHandle job, int kind, out BasicAccounting info,
            uint size, IntPtr returnedSize);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern KernelHandle CreateFileW(string path, uint access, uint sharing, ref SecurityAttributes security,
            uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value,
            IntPtr size, IntPtr previous, IntPtr returnedSize);
        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessW(string executable, StringBuilder commandLine, IntPtr processSecurity,
            IntPtr threadSecurity, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, IntPtr environment,
            string directory, ref StartupInfoEx startup, out ProcessInformation info);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint ResumeThread(KernelHandle thread);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateProcess(KernelHandle process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(KernelHandle handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetExitCodeProcess(KernelHandle process, out uint code);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);
    }
}
