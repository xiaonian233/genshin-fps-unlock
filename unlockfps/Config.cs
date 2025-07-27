namespace unlockfps
{
    public class Config
    {
        public string GamePath { get; set; } = "";

        //public bool AutoStart { get; set; } = false;
        //public bool AutoClose { get; set; } = false;
        //public bool PopupWindow { get; set; } = false;
        //public bool Fullscreen { get; set; } = true;
        //public bool UseCustomRes { get; set; } = false;
        //public bool IsExclusiveFullscreen { get; set; } = false;
        //public bool StartMinimized { get; set; } = false;
        public bool UsePowerSave { get; set; } = false;
        public bool SuspendLoad { get; set; } = false;
        //public bool UseMobileUI { get; set; } = false;

        public int FPSTarget { get; set; } = 144;
        //public int CustomResX { get; set; } = 1920;
        //public int CustomResY { get; set; } = 1080;
        public int MonitorNum { get; set; } = 1;
        public int Priority { get; set; } = 3;
        //public string AdditionalCommandLine { get; set; } = "";
    }
}
