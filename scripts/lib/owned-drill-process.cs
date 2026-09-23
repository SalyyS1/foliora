using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace Foliora.Drill
{
    // A root process and its job have separate lifetimes: an exited root can leave live children.
    public sealed class OwnedProcess : IDisposable
    {
        private readonly KernelHandle job;
        private readonly KernelHandle process;
        private int disposed;
        public int Id { get; }

        private OwnedProcess(KernelHandle job, KernelHandle process, int id)
        {
            this.job = job;
            this.process = process;
            Id = id;
        }

        public static OwnedProcess Start(string executable, string[] arguments, string workingDirectory,
            string stdoutPath, string stderrPath)
        {
            if (!OperatingSystem.IsWindowsVersionAtLeast(10))
                throw new PlatformNotSupportedException("Windows 10 or later is required.");
            if (arguments == null) throw new ArgumentNullException(nameof(arguments));
            workingDirectory = Path.GetFullPath(workingDirectory);
            executable = Path.GetFullPath(executable, workingDirectory);
            stdoutPath = Path.GetFullPath(stdoutPath, workingDirectory);
            stderrPath = Path.GetFullPath(stderrPath, workingDirectory);
            if (String.Equals(stdoutPath, stderrPath, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Standard output and error require separate files.");
            var commandLine = new StringBuilder(Quote(executable));
            foreach (string argument in arguments) commandLine.Append(' ').Append(Quote(argument));
            if (commandLine.Length >= 32767) throw new ArgumentException("Windows command line is too long.");

            // Allocate owning wrappers before CreateProcess so even setup failures retain the handles.
            var process = new KernelHandle();
            using var thread = new KernelHandle();
            KernelHandle job = null;
            bool transferred = false;
            try
            {
                job = OwnedProcessNative.CreateKillOnCloseJob();
                int id = OwnedProcessNative.CreateSuspended(executable, commandLine, workingDirectory,
                    stdoutPath, stderrPath, job, process, thread);
                var result = new OwnedProcess(job, process, id);
                if (OwnedProcessNative.ResumeThread(thread) == UInt32.MaxValue)
                    throw OwnedProcessNative.Error("ResumeThread");
                transferred = true;
                return result;
            }
            catch (Exception launchError)
            {
                // Creation associates the job atomically; later setup failures still terminate the child.
                if (!process.IsInvalid)
                {
                    try
                    {
                        OwnedProcessNative.Check(OwnedProcessNative.TerminateProcess(process, 1),
                            "TerminateProcess after launch failure");
                        if (!OwnedProcessNative.Wait(process, 10000))
                            throw new TimeoutException("Suspended child termination exceeded 10 seconds.");
                    }
                    catch (Exception cleanupError) { throw new AggregateException(launchError, cleanupError); }
                }
                throw;
            }
            finally
            {
                if (!transferred) { job?.Dispose(); process.Dispose(); }
            }
        }

        public bool HasExited => WaitForExit(0);

        public int ExitCode
        {
            get
            {
                if (!HasExited) throw new InvalidOperationException("The root process has not exited.");
                OwnedProcessNative.Check(OwnedProcessNative.GetExitCodeProcess(process, out uint code),
                    "GetExitCodeProcess");
                // 259 is a valid exit code once the process handle is signaled.
                return unchecked((int)code);
            }
        }

        // This waits only for the root, not for its descendants or inherited output handles.
        public bool WaitForExit(int milliseconds)
        {
            ValidateTimeout(milliseconds);
            ThrowIfDisposed();
            return OwnedProcessNative.Wait(process, milliseconds);
        }

        // Success means the job is empty, even if the original parent exited before this call.
        public void Stop(int milliseconds)
        {
            ValidateTimeout(milliseconds);
            ThrowIfDisposed();
            var timer = Stopwatch.StartNew();
            OwnedProcessNative.Check(OwnedProcessNative.TerminateJobObject(job, 1), "TerminateJobObject");
            while (true)
            {
                OwnedProcessNative.Check(OwnedProcessNative.QueryInformationJobObject(job, 1,
                    out OwnedProcessNative.BasicAccounting accounting,
                    (uint)System.Runtime.InteropServices.Marshal.SizeOf<OwnedProcessNative.BasicAccounting>(),
                    IntPtr.Zero), "QueryInformationJobObject");
                if (accounting.ActiveProcesses == 0)
                {
                    // Job accounting can reach zero just before the root's handle is signaled.
                    int rootBudget = (int)Math.Max(0, milliseconds - timer.ElapsedMilliseconds);
                    if (!OwnedProcessNative.Wait(process, rootBudget))
                        throw new TimeoutException("Owned root has not completed termination.");
                    return;
                }
                long remaining = milliseconds - timer.ElapsedMilliseconds;
                if (remaining <= 0) throw new TimeoutException("Owned job still has active processes.");
                Thread.Sleep((int)Math.Min(remaining, 20));
            }
        }

        // Closing the non-inherited job requests termination without an unbounded disposal wait.
        // Call Stop first when confirmed quiescence is required. SafeHandle also covers finalization.
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            job.Dispose();
            process.Dispose();
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref disposed) != 0) throw new ObjectDisposedException(nameof(OwnedProcess));
        }

        private static void ValidateTimeout(int milliseconds)
        {
            if (milliseconds < 0) throw new ArgumentOutOfRangeException(nameof(milliseconds),
                "A finite, non-negative timeout is required.");
        }

        // CRT parsing doubles backslashes only before quotes and before the closing quote.
        private static string Quote(string argument)
        {
            if (argument == null) throw new ArgumentNullException(nameof(argument));
            if (argument.IndexOf('\0') >= 0) throw new ArgumentException("Arguments cannot contain NUL.");
            var quoted = new StringBuilder("\"");
            int slashes = 0;
            foreach (char c in argument)
            {
                if (c == '\\') { slashes++; continue; }
                quoted.Append('\\', c == '"' ? slashes * 2 + 1 : slashes).Append(c);
                slashes = 0;
            }
            return quoted.Append('\\', slashes * 2).Append('"').ToString();
        }
    }
}
