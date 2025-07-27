using System.Runtime.InteropServices;
using System.Text;

namespace unlockfps
{
    internal class ProcessUtils
    {
        public static string GetProcessPathFromPid(uint pid, out IntPtr processHandle)
        {
            var hProcess = Native.OpenProcess(
                ProcessAccess.QUERY_LIMITED_INFORMATION |
                ProcessAccess.TERMINATE |
                StandardAccess.SYNCHRONIZE, false, pid);

            processHandle = hProcess;

            if (hProcess == IntPtr.Zero)
                return string.Empty;

            StringBuilder sb = new StringBuilder(1024);
            uint bufferSize = (uint)sb.Capacity;
            if (!Native.QueryFullProcessImageName(hProcess, 0, sb, ref bufferSize))
                return string.Empty;

            return sb.ToString();
        }

        public static IntPtr GetWindowFromProcessId(int processId)
        {
            IntPtr windowHandle = IntPtr.Zero;

            Native.EnumWindows((hWnd, lParam) =>
            {
                Native.GetWindowThreadProcessId(hWnd, out uint pid);
                if (pid == processId)
                {
                    windowHandle = hWnd;
                    return false;
                }

                return true;
            }, IntPtr.Zero);

            return windowHandle;
        }

        public static unsafe List<IntPtr> PatternScanAllOccurrences(IntPtr module, string signature)
        {
            var (patternBytes, maskBytes) = ParseSignature(signature);

            var sizeOfImage = Native.GetModuleImageSize(module);
            var scanBytes = (byte*)module;

            if (Native.IsWine())
                Native.VirtualProtect(module, sizeOfImage, MemoryProtection.EXECUTE_READWRITE, out _);

            var span = new ReadOnlySpan<byte>(scanBytes, (int)sizeOfImage);
            var offsets = new List<IntPtr>();

            var totalProcessed = 0L;
            while (true)
            {
                var offset = PatternScan(span, patternBytes, maskBytes);
                if (offset == -1)
                    break;

                offsets.Add((IntPtr)(module.ToInt64() + offset + totalProcessed));

                var processedOffset = offset + patternBytes.Length;
                totalProcessed += processedOffset;

                span = span.Slice((int)processedOffset);
            }

            return offsets;
        }

        public static long PatternScan(ReadOnlySpan<byte> data, byte[] patternBytes, bool[] maskBytes)
        {
            var s = patternBytes.Length;
            var d = patternBytes;

            for (var i = 0; i < data.Length - s; i++)
            {
                var found = true;
                for (var j = 0; j < s; j++)
                {
                    if (d[j] != data[i + j] && !maskBytes[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                    return i;
            }

            return -1;
        }

        private static (byte[], bool[]) ParseSignature(string signature)
        {
            var tokens = signature.Split(' ');
            var patternBytes = tokens
                .Select(x => x == "?" ? (byte)0xFF : Convert.ToByte(x, 16))
                .ToArray();
            var maskBytes = tokens
                .Select(x => x == "?")
                .ToArray();

            return (patternBytes, maskBytes);
        }

        public static IntPtr GetModuleBase(IntPtr hProcess, string moduleName)
        {
            var moduleNameLower = moduleName.ToLowerInvariant();
            var modules = new IntPtr[1024];

            if (!Native.EnumProcessModulesEx(hProcess, modules, (uint)(modules.Length * IntPtr.Size), out var bytesNeeded, 2))
            {
                var errorCode = Marshal.GetLastWin32Error();
                if (errorCode != 299)
                {
                    Console.WriteLine($@"EnumProcessModulesEx failed ({errorCode}){Environment.NewLine}{Marshal.GetLastPInvokeErrorMessage()}"
                        , @"Error");
                    return IntPtr.Zero;
                }
            }

            foreach (var module in modules.Where(x => x != IntPtr.Zero))
            {
                StringBuilder sb = new StringBuilder(1024);
                if (Native.GetModuleBaseName(hProcess, module, sb, (uint)sb.Capacity) == 0)
                    continue;

                if (sb.ToString().ToLowerInvariant() != moduleNameLower)
                    continue;

                if (!Native.GetModuleInformation(hProcess, module, out var moduleInfo, (uint)Marshal.SizeOf<MODULEINFO>()))
                    continue;

                return moduleInfo.lpBaseOfDll;
            }

            return IntPtr.Zero;
        }

    }
}
