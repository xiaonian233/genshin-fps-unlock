using System.Runtime.InteropServices;

namespace unlockfps
{
    public class Program
    {
        private static IntPtr MutexHandle = IntPtr.Zero;
        private static IntPtr hWnd = Native.GetConsoleWindow();
        public static string CommandLine = "";
        public static void showwindow(int status)
        {
            Native.ShowWindow(hWnd, status);
        }
        static void Main(string[] args) {
            MutexHandle = Native.CreateMutex(IntPtr.Zero, true, @"fpsunlocker");
            if (Marshal.GetLastWin32Error() == 183)
            {
                showwindow(5);
                Console.WriteLine(@"[Error]：Another fpsunlocker is already running.");
                return;
            }
            /*
             * SW_HIDE = 0;
             * SW_SHOW = 5;
             */
            showwindow(0);
            if (args.Length > 0)
            {
                for (int i = 0; i < args.Length; i++)
                    CommandLine += args[i] + " ";
            }
            var configService = new ConfigService();
            var ipcService = new IpcService();
            // 创建 ProcessService 实例
            var processService = new ProcessService(configService, ipcService);
            if (processService.Start())
                Console.ReadKey();
        }
    }
}