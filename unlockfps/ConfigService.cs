using System.Runtime.InteropServices;
using System.Text;

namespace unlockfps
{
    public class ConfigService
    {
        [DllImport("kernel32")]
        private static extern int GetPrivateProfileString(string section, string key, string defaultValue, StringBuilder retVal, int size, string filePath);
        [DllImport("kernel32")]
        private static extern int WritePrivateProfileString(string lpApplicationName,string lpKeyName,string lpString,string lpFileName);
        private const string ConfigName = "fps_config.ini";
        private string GamePath = "";

        public Config Config { get; private set; } = new();

        public ConfigService()
        {
            Load();
            Sanitize();
        }

        private void Load()
        {
            string appPath = AppDomain.CurrentDomain.BaseDirectory;
            string filePath = Path.Combine(appPath, ConfigName);

            if (!File.Exists(filePath))
            {
                Program.showwindow(5);
                Console.WriteLine($"游戏目录不存在，请手动启动原神");
                IntPtr windowHandle = IntPtr.Zero;
                IntPtr processHandle = IntPtr.Zero;
                while (true)
                {
                    Native.EnumWindows((hWnd, lParam) =>
                    {
                        StringBuilder className = new StringBuilder(256);
                        Native.GetClassName(hWnd, className, 256);
                        if (className.ToString() == "UnityWndClass")
                        {
                            Native.GetWindowThreadProcessId(hWnd, out var pid);
                            GamePath = ProcessUtils.GetProcessPathFromPid(pid, out processHandle);
                            if (GamePath.Contains("YuanShen.exe") || GamePath.Contains("GenshinImpact.exe"))
                            {
                                windowHandle = hWnd;
                                return false;
                            }
                        }
                        return true;
                    }, IntPtr.Zero);

                    if (windowHandle != IntPtr.Zero)
                    {
                        Native.TerminateProcess(processHandle, 0);
                        Native.CloseHandle(processHandle);
                        break;
                    }
                }

                if (string.IsNullOrEmpty(GamePath))
                {
                    Console.WriteLine("[ERROR]：Failed to find process path\n");
                    return;
                }

                Console.WriteLine($"Game Found!\n{GamePath}");
                File.Create(filePath).Close();
                WritePrivateProfileString("Setting", "Path", GamePath, filePath);
                WritePrivateProfileString("Setting", "FPS", "120", filePath);
            }

            StringBuilder value = new StringBuilder(255);
            GetPrivateProfileString("Setting", "Path", "Not Found", value, 255, filePath);
            string pathValue = value.ToString();

            GetPrivateProfileString("Setting", "FPS", "0", value, 255, filePath);
            int fpsValue = int.Parse(value.ToString());

            try
            {
                Config = new Config
                {
                    GamePath = pathValue,
                    FPSTarget = fpsValue
                };
            }
            catch (Exception)
            {
                Console.WriteLine(
                    $"Failed to load config file\nYour config file doesn't appear to be in the correct format. It will be reset to default.",
                    "Warning");
                Config = new();
            }
        }
        private void Sanitize()
        {
            Config.FPSTarget = Math.Clamp(Config.FPSTarget, 1, 420);
            Config.Priority = Math.Clamp(Config.Priority, 0, 5);
            //Config.CustomResX = Math.Clamp(Config.CustomResX, 200, 7680);
            //Config.CustomResY = Math.Clamp(Config.CustomResY, 200, 4320);
            Config.MonitorNum = Math.Clamp(Config.MonitorNum, 1, 100);
        }
    }
}
