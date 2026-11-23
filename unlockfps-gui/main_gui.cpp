// 原神 FPS 解锁器 GUI 版
// 基于 xiaonian233/genshin-fps-unlock (unlockfps 6.7) 核心逻辑移植
// 全部 UI 使用宽字符，与系统代码页无关；无控制台窗口
#define KEY_TOGGLE VK_F9
#define KEY_INCREASE VK_UP
#define KEY_INCREASE_SMALL VK_RIGHT
#define KEY_DECREASE VK_DOWN
#define KEY_DECREASE_SMALL VK_LEFT
#define FPS_TARGET 120

#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <Psapi.h>
#include <shellapi.h>
#include <cstdio>
#include <cstdarg>
#include "inireader.h"

// ---------------- 全局状态 ----------------
HINSTANCE g_inst = nullptr;
HWND g_hwnd = nullptr, g_edFps = nullptr, g_edArgs = nullptr, g_chkTray = nullptr,
     g_btnStart = nullptr, g_lblPath = nullptr, g_lblNow = nullptr, g_edLog = nullptr;
HFONT g_font = nullptr;

std::string GamePath{};
int FpsValue = FPS_TARGET;          // 该全局变量地址会被注入游戏进程的 shellcode 读取，必须保持为全局
int HideValue = 0;
std::string ArgsValue{};

volatile int g_TargetFPS = FPS_TARGET;
volatile int g_DisplayFPS = FPS_TARGET;
volatile bool g_DisplayOn = false;
volatile bool g_GameRunning = false;
volatile bool g_WorkerBusy = false;
HANDLE g_hGame = nullptr;
uintptr_t g_pfps = 0;
uintptr_t g_PatchPtr = 0;

// 自定义消息
#define WMU_TRAY  (WM_APP + 1)   // lParam = 鼠标消息
#define WMU_FPS   (WM_APP + 2)   // lParam = fps
#define WMU_STATE (WM_APP + 3)   // wParam: 0=空闲 1=工作中/游戏中

// 控件 ID
#define IDC_EDFPS    101
#define IDC_BTNSET   102
#define IDC_EDARGS   103
#define IDC_CHKTRAY  104
#define IDC_BTNSTART 105
#define IDC_LBLPATH  106
#define IDC_LBLNOW   107
#define IDC_EDLOG    108

#define IDM_SHOW 2001
#define IDM_EXIT 2002

NOTIFYICONDATAW g_nid{};
bool g_trayVisible = false;

// ---------------- 编码转换 ----------------
static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}
static std::string WideToUtf8(const WCHAR* w) {
    int len = lstrlenW(w);
    if (!len) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w, len, nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w, len, s.data(), n, nullptr, nullptr);
    return s;
}

// ---------------- 日志 ----------------
static void LogW(const WCHAR* fmt, ...) {
    if (!g_edLog) return;
    WCHAR buf[1024];
    va_list ap; va_start(ap, fmt);
    wvsprintfW(buf, fmt, ap);
    va_end(ap);
    lstrcatW(buf, L"\r\n");
    int len = GetWindowTextLengthW(g_edLog);
    if (len > 30000) {  // 裁剪旧日志
        SendMessageW(g_edLog, EM_SETSEL, 0, 15000);
        SendMessageW(g_edLog, EM_REPLACESEL, FALSE, (LPARAM)L"");
        len = GetWindowTextLengthW(g_edLog);
    }
    SendMessageW(g_edLog, EM_SETSEL, len, len);
    SendMessageW(g_edLog, EM_REPLACESEL, FALSE, (LPARAM)buf);
    SendMessageW(g_edLog, EM_SCROLLCARET, 0, 0);
}
static void LogA(const char* fmt, ...) {  // fmt 与字符串字面量均为 UTF-8
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    std::wstring w = Utf8ToWide(buf);
    LogW(L"%s", w.c_str());
}
void SetPathLabel()
{
    std::wstring wp = L"游戏路径: " + Utf8ToWide(GamePath);
    if (wp.length() > 74) wp = wp.substr(0, 72) + L"…";
    SetDlgItemTextW(g_hwnd, IDC_LBLPATH, wp.c_str());
}

// ---------------- 核心逻辑（与原版一致） ----------------
// credit by winTEuser
const BYTE _shellcode_genshin_Const[] =
{
    0x00, 0x00, 0x00, 0x00,
    0x00, 0xC0, 0x9C, 0x66,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0x48, 0x83, 0xEC, 0x38,
    0x8B, 0x05, 0xA6, 0xFF, 0xFF, 0xFF,
    0x85, 0xC0,
    0x74, 0x5C,
    0x41, 0x89, 0xC0,
    0x33, 0xD2,
    0xB9, 0xFF, 0xFF, 0x1F, 0x00,
    0xFF, 0x15, 0xA2, 0xFF, 0xFF, 0xFF,
    0x85, 0xC0,
    0x74, 0x48,
    0x89, 0xC6,
    0x48, 0x8B, 0x3D, 0x8D, 0xFF, 0xFF, 0xFF,
    0x0F, 0x1F, 0x44, 0x00, 0x00,
    0x89, 0xF1,
    0x48, 0x89, 0xFA,
    0x4C, 0x8D, 0x05, 0x08, 0x01, 0x00, 0x00,
    0x41, 0xB9, 0x04, 0x00, 0x00, 0x00,
    0x31, 0xC0,
    0x48, 0x89, 0x44, 0x24, 0x20,
    0xFF, 0x15, 0x79, 0xFF, 0xFF, 0xFF,
    0x85, 0xC0,
    0x74, 0x12,
    0xB9, 0xF4, 0x01, 0x00, 0x00,
    0xFF, 0x15, 0x72, 0xFF, 0xFF, 0xFF,
    0xE8, 0x5D, 0x00, 0x00, 0x00,
    0xEB, 0xCB,
    0xE8, 0x76, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xC4, 0x38,
    0xC3,
    0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0x89, 0x0D, 0xBA, 0x00, 0x00, 0x00,
    0x31, 0xC0,
    0x83, 0xF9, 0x1E,
    0x74, 0x0E,
    0x83, 0xF9, 0x2D,
    0x74, 0x15,
    0x2E, 0xB9, 0xE8, 0x03, 0x00, 0x00,
    0xEB, 0x06,
    0xCC,
    0xB9, 0x3C, 0x00, 0x00, 0x00,
    0x89, 0x0D, 0x0B, 0x00, 0x00, 0x00,
    0xC3,
    0x8B, 0x0D, 0x97, 0x00, 0x00, 0x00,
    0xEB, 0xF1,
    0xCC,
    0xB8, 0x78, 0x00, 0x00, 0x00,
    0xC3,
    0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0x8B, 0x05, 0x7A, 0x00, 0x00, 0x00,
    0x83, 0xF8, 0x2D,
    0x75, 0x0C,
    0x8B, 0x05, 0x73, 0x00, 0x00, 0x00,
    0x89, 0x05, 0xDA, 0xFF, 0xFF, 0xFF,
    0xC3,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0x48, 0x83, 0xEC, 0x28,
    0x31, 0xC9,
    0x48, 0x8D, 0x15, 0x33, 0x00, 0x00, 0x00,
    0x4C, 0x8D, 0x05, 0x3C, 0x00, 0x00, 0x00,
    0x41, 0xB9, 0x10, 0x00, 0x00, 0x00,
    0xFF, 0x15, 0xD8, 0xFE, 0xFF, 0xFF,
    0x89, 0xF1,
    0xFF, 0x15, 0xD8, 0xFE, 0xFF, 0xFF,
    0x48, 0x83, 0xC4, 0x28,
    0xC3,
    0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    'S','y','n','c',' ','f','a','i','l','e','d','!', 0x00, 0x00, 0x00, 0x00,
    'E','r','r','o','r', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uintptr_t PatternScan_Region(uintptr_t startAddress, size_t regionSize, const char* signature)
{
    auto pattern_to_byte = [](const char* pattern) {
        std::vector<int> bytes;
        const char* start = pattern;
        const char* end = pattern + strlen(pattern);
        for (const char* current = start; current < end; ++current) {
            if (*current == '?') { ++current; if (*current == '?') ++current; bytes.push_back(-1); }
            else bytes.push_back(strtoul(current, const_cast<char**>(&current), 16));
        }
        return bytes;
    };
    std::vector<int> patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t*>(startAddress);
    for (size_t i = 0; i < regionSize - patternBytes.size(); ++i) {
        bool found = true;
        for (size_t j = 0; j < patternBytes.size(); ++j) {
            if (scanBytes[i + j] != patternBytes[j] && patternBytes[j] != -1) { found = false; break; }
        }
        if (found) return (uintptr_t)&scanBytes[i];
    }
    return 0;
}

static bool GetModule(DWORD pid, std::string ModuleName, PMODULEENTRY32 pEntry)
{
    if (!pEntry) return false;
    MODULEENTRY32 mod32{};
    mod32.dwSize = sizeof(mod32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    bool temp = Module32First(snap, &mod32);
    if (temp) {
        do {
            if (mod32.th32ProcessID != pid) break;
            if (mod32.szModule == ModuleName) { *pEntry = mod32; CloseHandle(snap); return 1; }
        } while (Module32Next(snap, &mod32));
    }
    CloseHandle(snap);
    return 0;
}

DWORD GetPID(std::string ProcessName)
{
    DWORD pid = 0;
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(pe32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    for (Process32First(snap, &pe32); Process32Next(snap, &pe32);) {
        if (pe32.szExeFile == ProcessName) { pid = pe32.th32ProcessID; break; }
    }
    CloseHandle(snap);
    return pid;
}

static bool WaitForBaseModule(DWORD pid, const std::string& procname, MODULEENTRY32& out, DWORD timeout_ms = 50000)
{
    const DWORD step = 50;
    DWORD waited = 0;
    while (waited < timeout_ms) {
        if (GetModule(pid, procname, &out)) return true;
        Sleep(step);
        waited += step;
    }
    return false;
}

bool WriteConfig(std::string path, int fps, int hide, const std::string& args)
{
    HANDLE hFile = CreateFileA("fps_config.ini", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    std::string content = "[Setting]\n";
    content += "Path=" + path + "\n";
    content += "FPS=" + std::to_string(fps) + "\n";
    content += "hide=" + std::to_string(hide) + "\n";
    content += "Args=" + args;
    DWORD written = 0;
    WriteFile(hFile, content.data(), (DWORD)content.size(), &written, nullptr);
    CloseHandle(hFile);
    return true;
}

// 注入 shellcode 到游戏进程（与原版一致）
static DWORD64 inject_patch(LPVOID text_buffer, DWORD text_size, DWORD64 _text_baseaddr, uint64_t _ptr_fps, HANDLE Tar_handle)
{
    if (!text_buffer || !text_size || !_text_baseaddr || !_ptr_fps || !Tar_handle) return 0;

    uint64_t _shellcode_buffer = (uint64_t)VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!_shellcode_buffer) { LogA("本地内存分配失败"); return 0; }
    memcpy((void*)_shellcode_buffer, &_shellcode_genshin_Const, sizeof(_shellcode_genshin_Const));

    *(uint32_t*)_shellcode_buffer = GetCurrentProcessId();
    *(uint64_t*)(_shellcode_buffer + 8) = (uint64_t)(&FpsValue);
    *(uint64_t*)(_shellcode_buffer + 16) = (uint64_t)(&OpenProcess);
    *(uint64_t*)(_shellcode_buffer + 24) = (uint64_t)(&ReadProcessMemory);
    *(uint64_t*)(_shellcode_buffer + 32) = (uint64_t)(&Sleep);
    *(uint64_t*)(_shellcode_buffer + 40) = (uint64_t)(&MessageBoxA);
    *(uint64_t*)(_shellcode_buffer + 48) = (uint64_t)(&CloseHandle);
    *(uint32_t*)(_shellcode_buffer + 0xE4) = 1000;
    *(uint32_t*)(_shellcode_buffer + 0xEC) = 60;
    *(uint64_t*)(_shellcode_buffer + 0x110) = 0xB848;
    *(uint64_t*)(_shellcode_buffer + 0x118) = 0x741D8B0000;
    *(uint64_t*)(_shellcode_buffer + 0x120) = 0xCCCCCCCCCCC31889;
    *(uint64_t*)(_shellcode_buffer + 0x112) = _ptr_fps;
    *(uint64_t*)(_shellcode_buffer + 0x15C) = 0x5C76617E8834858;
    *(uint64_t*)(_shellcode_buffer + 0x164) = 0xE0FF21EBFFFFFF16;

    LPVOID __Tar_proc_buffer = VirtualAllocEx(Tar_handle, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!__Tar_proc_buffer) {
        LogA("游戏进程内存分配失败");
        VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);
        return 0;
    }
    if (!WriteProcessMemory(Tar_handle, __Tar_proc_buffer, (void*)_shellcode_buffer, sizeof(_shellcode_genshin_Const), 0)) {
        LogA("注入失败");
        VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);
        return 0;
    }
    VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);

    HANDLE temp = CreateRemoteThread(Tar_handle, 0, 0, (LPTHREAD_START_ROUTINE)((uint64_t)__Tar_proc_buffer + 0x50), 0, 0, 0);
    if (!temp) { LogA("创建游戏内同步线程失败"); return 0; }
    CloseHandle(temp);
    return ((uint64_t)__Tar_proc_buffer + 0x194);
}

// ---------------- 配置 ----------------
bool EnsureConfig()
{
    if (GetFileAttributesA("fps_config.ini") == INVALID_FILE_ATTRIBUTES) {
        LogA("首次运行：请手动启动一次游戏，用于获取游戏路径（只需一次）…");
        DWORD pid = 0;
        while (!(pid = GetPID("YuanShen.exe")) && !(pid = GetPID("GenshinImpact.exe")))
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess) { LogA("OpenProcess 失败 (%d)", GetLastError()); return false; }
        char szPath[MAX_PATH]{};
        DWORD length = sizeof(szPath);
        QueryFullProcessImageNameA(hProcess, 0, szPath, &length);
        GamePath = szPath;
        WriteConfig(GamePath, FpsValue, HideValue, ArgsValue);
        LogA("已获取路径，等待游戏关闭…");

        HWND hwnd = nullptr;
        while (!(hwnd = FindWindowA("UnityWndClass", nullptr)))
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        DWORD ExitCode = STILL_ACTIVE;
        while (ExitCode == STILL_ACTIVE) {
            SendMessageA(hwnd, WM_CLOSE, 0, 0);
            GetExitCodeProcess(hProcess, &ExitCode);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        WaitForSingleObject(hProcess, INFINITE);
        CloseHandle(hProcess);
        LogA("路径已保存，点击“启动游戏”继续");
    }

    INIReader reader("fps_config.ini");
    if (reader.ParseError() != 0) return false;
    GamePath = reader.Get("Setting", "Path", "");
    FpsValue = reader.GetInteger("Setting", "FPS", FpsValue);
    HideValue = reader.GetInteger("Setting", "hide", HideValue);
    ArgsValue = reader.Get("Setting", "Args", ArgsValue);
    if (GamePath.length() < 8) return false;

    if (GetFileAttributesA(GamePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LogA("配置中的游戏路径已失效，请删除 fps_config.ini 后重试");
        return false;
    }
    return true;
}

// ---------------- 热键线程 ----------------
DWORD WINAPI HotkeyThread(LPVOID)
{
    int fps = g_TargetFPS;
    int prev = fps;
    while (g_GameRunning) {
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
        if (GetAsyncKeyState(KEY_DECREASE) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000) fps -= 20;
        if (GetAsyncKeyState(KEY_DECREASE_SMALL) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000) fps -= 2;
        if (GetAsyncKeyState(KEY_INCREASE) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000) fps += 20;
        if (GetAsyncKeyState(KEY_INCREASE_SMALL) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000) fps += 2;
        if (GetAsyncKeyState(KEY_TOGGLE) & 1) fps = fps != 60 ? 60 : prev;
        if (prev != fps) WriteConfig(GamePath, fps, HideValue, ArgsValue);
        if (fps > 60) prev = fps;
        if (fps < 60) fps = 60;
        if (fps != g_TargetFPS) {
            g_TargetFPS = fps;
            g_DisplayFPS = fps;
            g_DisplayOn = fps > 60;
            PostMessage(g_hwnd, WMU_FPS, 0, fps);
        }
    }
    return 0;
}

// ---------------- 游戏工作线程（原 main 流程） ----------------
DWORD WINAPI GameWorker(LPVOID)
{
    g_WorkerBusy = true;
    PostMessage(g_hwnd, WMU_STATE, 1, 0);

    if (!EnsureConfig()) {
        LogA("初始化未完成");
        g_WorkerBusy = false;
        PostMessage(g_hwnd, WMU_STATE, 0, 0);
        return 0;
    }
    g_TargetFPS = FpsValue;
    g_DisplayFPS = FpsValue;
    g_DisplayOn = FpsValue > 60;
    PostMessage(g_hwnd, WMU_FPS, 0, FpsValue);
    SetPathLabel();

    std::string ProcessPath = GamePath;
    std::string ProcessDir = ProcessPath.substr(0, ProcessPath.find_last_of("\\"));
    std::string procname = ProcessPath.substr(ProcessPath.find_last_of("\\") + 1);

    if (GetPID(procname)) {
        LogA("检测到游戏已在运行，请先关闭游戏再启动");
        g_WorkerBusy = false;
        PostMessage(g_hwnd, WMU_STATE, 0, 0);
        return 0;
    }

    std::string cmdline = "\"" + ProcessPath + "\"";
    if (!ArgsValue.empty()) cmdline += " " + ArgsValue;

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(ProcessPath.c_str(), cmdline.data(), nullptr, nullptr, FALSE, 0, nullptr, ProcessDir.c_str(), &si, &pi)) {
        LogA("启动游戏失败 (%d)", GetLastError());
        g_WorkerBusy = false;
        PostMessage(g_hwnd, WMU_STATE, 0, 0);
        return 0;
    }
    CloseHandle(pi.hThread);
    g_hGame = pi.hProcess;
    LogA("游戏 PID: %d", pi.dwProcessId);
    Sleep(200);
    SetPriorityClass(pi.hProcess, HIGH_PRIORITY_CLASS);

    MODULEENTRY32 hBaseModule{};
    if (!WaitForBaseModule(pi.dwProcessId, procname, hBaseModule)) {
        LogA("获取游戏主模块失败");
        CloseHandle(pi.hProcess); g_hGame = nullptr;
        g_WorkerBusy = false;
        PostMessage(g_hwnd, WMU_STATE, 0, 0);
        return 0;
    }
    LogA("主模块基址: 0x%llX", (unsigned long long)(uintptr_t)hBaseModule.modBaseAddr);

    LPVOID _mbase_PE_buffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!_mbase_PE_buffer || !hBaseModule.modBaseAddr || ReadProcessMemory(pi.hProcess, hBaseModule.modBaseAddr, _mbase_PE_buffer, 0x1000, 0) == 0) {
        LogA("读取 PE 头失败");
        if (_mbase_PE_buffer) VirtualFree(_mbase_PE_buffer, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess); g_hGame = nullptr;
        g_WorkerBusy = false;
        PostMessage(g_hwnd, WMU_STATE, 0, 0);
        return 0;
    }

    BYTE search_sec[8] = ".text";
    uint64_t tar_sec = *(uint64_t*)&search_sec;
    uintptr_t WinPEfileVA = *(uintptr_t*)(&_mbase_PE_buffer) + 0x3c;
    uintptr_t PEfptr = *(uintptr_t*)(&_mbase_PE_buffer) + *(uint32_t*)WinPEfileVA;
    _IMAGE_NT_HEADERS64 _FilePE_Nt_header = *(_IMAGE_NT_HEADERS64*)PEfptr;
    _IMAGE_SECTION_HEADER _sec_temp{};
    uintptr_t Text_Remote_RVA = 0;
    uint32_t Text_Vsize = 0;
    bool foundSec = false;
    if (_FilePE_Nt_header.Signature == 0x00004550) {
        DWORD sec_num = _FilePE_Nt_header.FileHeader.NumberOfSections;
        DWORD num = sec_num;
        while (num) {
            _sec_temp = *(_IMAGE_SECTION_HEADER*)(PEfptr + 264 + (40 * (static_cast<unsigned long long>(sec_num) - num)));
            if (*(uint64_t*)(_sec_temp.Name) == tar_sec) {
                Text_Remote_RVA = (uintptr_t)hBaseModule.modBaseAddr + _sec_temp.VirtualAddress;
                Text_Vsize = _sec_temp.Misc.VirtualSize;
                foundSec = true;
                break;
            }
            num--;
        }
    }
    if (!foundSec) {
        LogA("PE 结构无效");
        VirtualFree(_mbase_PE_buffer, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess); g_hGame = nullptr;
        g_WorkerBusy = false;
        PostMessage(g_hwnd, WMU_STATE, 0, 0);
        return 0;
    }

    LPVOID Copy_Text_VA = VirtualAlloc(0, Text_Vsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Copy_Text_VA || ReadProcessMemory(pi.hProcess, (void*)Text_Remote_RVA, Copy_Text_VA, Text_Vsize, 0) == 0) {
        LogA("读取 .text 节失败");
        VirtualFree(_mbase_PE_buffer, 0, MEM_RELEASE);
        if (Copy_Text_VA) VirtualFree(Copy_Text_VA, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess); g_hGame = nullptr;
        g_WorkerBusy = false;
        PostMessage(g_hwnd, WMU_STATE, 0, 0);
        return 0;
    }

    LogA("正在搜索特征码…");
    uintptr_t address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "8B 0D ?? ?? ?? ?? EB ?? 33 C0");
    if (!address) {
        LogA("特征码未找到：游戏版本可能已更新，等待解锁器更新");
        VirtualFree(_mbase_PE_buffer, 0, MEM_RELEASE);
        VirtualFree(Copy_Text_VA, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess); g_hGame = nullptr;
        g_WorkerBusy = false;
        PostMessage(g_hwnd, WMU_STATE, 0, 0);
        return 0;
    }
    uintptr_t pfps = 0;
    {
        uintptr_t rip = address + 6;
        int32_t offset = *(int32_t*)(address + 2);
        uintptr_t local_fps_addr = rip + offset;
        pfps = local_fps_addr - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
    }
    g_pfps = pfps;
    LogA("FPS 变量地址: 0x%llX", (unsigned long long)pfps);

    g_PatchPtr = inject_patch(Copy_Text_VA, Text_Vsize, Text_Remote_RVA, pfps, pi.hProcess);
    if (!g_PatchPtr) LogA("注入未完成，帧率同步不可用");

    VirtualFree(_mbase_PE_buffer, 0, MEM_RELEASE);
    VirtualFree(Copy_Text_VA, 0, MEM_RELEASE);
    LogA("完成，游戏已启动");
    g_GameRunning = true;

    HANDLE hThread = CreateThread(nullptr, 0, HotkeyThread, nullptr, 0, nullptr);
    if (hThread) CloseHandle(hThread);

    DWORD dwExitCode = STILL_ACTIVE;
    while (dwExitCode == STILL_ACTIVE) {
        GetExitCodeProcess(pi.hProcess, &dwExitCode);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        int current_fps = 0;
        if (ReadProcessMemory(pi.hProcess, (LPVOID)pfps, &current_fps, sizeof(current_fps), nullptr)) {
            if (current_fps == -1) continue;
            if (current_fps != g_TargetFPS)
                WriteProcessMemory(pi.hProcess, (LPVOID)g_PatchPtr, (LPVOID)&g_TargetFPS, 4, nullptr);
        }
    }

    g_GameRunning = false;
    CloseHandle(pi.hProcess);
    g_hGame = nullptr; g_pfps = 0; g_PatchPtr = 0;
    g_DisplayFPS = 60; g_DisplayOn = false;
    LogA("游戏已退出");
    g_WorkerBusy = false;
    PostMessage(g_hwnd, WMU_STATE, 0, 0);
    return 0;
}

// ---------------- 托盘 ----------------
void TrayAdd()
{
    if (g_trayVisible) return;
    Shell_NotifyIconW(NIM_ADD, &g_nid);
    g_trayVisible = true;
}
void TrayRemove()
{
    if (!g_trayVisible) return;
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
    g_trayVisible = false;
}
void HideToTray()
{
    TrayAdd();
    ShowWindow(g_hwnd, SW_HIDE);
}
void RestoreFromTray()
{
    ShowWindow(g_hwnd, SW_SHOW);
    SetForegroundWindow(g_hwnd);
}

// 退出前把游戏帧率恢复到 60
void RestoreFpsOnExit()
{
    if (g_hGame && g_pfps) {
        int s60 = 60;
        WriteProcessMemory(g_hGame, (LPVOID)g_pfps, &s60, 4, nullptr);
    }
}

// ---------------- UI ----------------
static HWND Mk(const WCHAR* cls, const WCHAR* text, DWORD style, int x, int y, int w, int h, int id)
{
    HWND ctl = CreateWindowExW(0, cls, text, style | WS_CHILD | WS_VISIBLE, x, y, w, h,
        g_hwnd, (HMENU)(INT_PTR)id, g_inst, nullptr);
    SendMessageW(ctl, WM_SETFONT, (WPARAM)g_font, TRUE);
    return ctl;
}

void ApplyFpsFromUI()
{
    BOOL ok = FALSE;
    int v = GetDlgItemInt(g_hwnd, IDC_EDFPS, &ok, FALSE);
    if (!ok) { LogA("请输入有效数字"); return; }
    if (v < 60) v = 60;
    if (v > 1000) v = 1000;
    FpsValue = v;
    g_TargetFPS = v;
    g_DisplayFPS = v;
    g_DisplayOn = v > 60;
    SetDlgItemInt(g_hwnd, IDC_EDFPS, v, FALSE);
    if (!GamePath.empty()) WriteConfig(GamePath, FpsValue, HideValue, ArgsValue);
    LogA("FPS 上限已设为 %d", v);
}

void OnStart()
{
    if (g_WorkerBusy) return;
    ApplyFpsFromUI();
    WCHAR args[512]{};
    GetWindowTextW(g_edArgs, args, 511);
    ArgsValue = WideToUtf8(args);
    HideValue = (SendMessageW(g_chkTray, BM_GETCHECK, 0, 0) == BST_CHECKED) ? 1 : 0;
    if (!GamePath.empty()) WriteConfig(GamePath, FpsValue, HideValue, ArgsValue);
    CloseHandle(CreateThread(nullptr, 0, GameWorker, nullptr, 0, nullptr));
}

void LoadIniToUI()
{
    INIReader reader("fps_config.ini");
    if (reader.ParseError() != 0) return;
    GamePath = reader.Get("Setting", "Path", "");
    FpsValue = reader.GetInteger("Setting", "FPS", FPS_TARGET);
    ArgsValue = reader.Get("Setting", "Args", "");
    HideValue = reader.GetInteger("Setting", "hide", 0);
    if (FpsValue < 60) FpsValue = 60;
    SetDlgItemInt(g_hwnd, IDC_EDFPS, FpsValue, FALSE);
    SetWindowTextW(g_edArgs, Utf8ToWide(ArgsValue).c_str());
    SendMessageW(g_chkTray, BM_SETCHECK, HideValue ? BST_CHECKED : BST_UNCHECKED, 0);
    if (!GamePath.empty()) SetPathLabel();
    g_TargetFPS = FpsValue;
    g_DisplayFPS = FpsValue;
    g_DisplayOn = FpsValue > 60;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;  // CreateWindowW 返回前 g_hwnd 尚未赋值，子控件创建前必须先设置
        g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        Mk(L"STATIC", L"帧率上限:", 0, 10, 12, 60, 18, 0);
        g_edFps = Mk(L"EDIT", L"120", WS_BORDER | ES_NUMBER, 72, 10, 70, 20, IDC_EDFPS);
        Mk(L"BUTTON", L"设置", BS_PUSHBUTTON, 150, 9, 60, 22, IDC_BTNSET);
        g_lblNow = Mk(L"STATIC", L"", 0, 220, 12, 250, 18, IDC_LBLNOW);
        Mk(L"STATIC", L"启动参数(可选):", 0, 10, 40, 110, 18, 0);
        g_edArgs = Mk(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 120, 38, 350, 20, IDC_EDARGS);
        g_chkTray = Mk(L"BUTTON", L"启动后隐藏到托盘", BS_AUTOCHECKBOX, 10, 66, 160, 20, IDC_CHKTRAY);
        g_btnStart = Mk(L"BUTTON", L"启动游戏", BS_PUSHBUTTON, 330, 62, 140, 28, IDC_BTNSTART);
        g_lblPath = Mk(L"STATIC", L"游戏路径: (尚未配置)", 0, 10, 94, 460, 18, IDC_LBLPATH);
        g_edLog = Mk(L"EDIT", L"", WS_BORDER | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
            10, 122, 460, 292, IDC_EDLOG);
        Mk(L"STATIC", L"热键：F9 开/关　右Ctrl+↑/↓：±20　右Ctrl+←/→：±2　（按一次改一次）", 0, 10, 424, 460, 18, 0);
        Mk(L"STATIC", L"本程序须保持运行；关闭窗口会最小化到托盘，退出前自动恢复 60 帧。", 0, 10, 444, 460, 18, 0);

        g_nid.cbSize = sizeof(g_nid);
        g_nid.hWnd = hwnd;
        g_nid.uID = 1;
        g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        g_nid.uCallbackMessage = WMU_TRAY;
        g_nid.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(IDI_APPLICATION));
        lstrcpyW(g_nid.szTip, L"原神 FPS 解锁器");

        LoadIniToUI();
        SetTimer(hwnd, 1, 200, nullptr);
        LogA("就绪。点击“启动游戏”开始（首次运行需先手动开一次游戏以获取路径）。");
        return 0;
    }
    case WM_TIMER:
        if (wParam == 1) {
            WCHAR buf[64];
            wsprintfW(buf, L"当前: %d (%s)", g_DisplayFPS, g_DisplayOn ? L"ON" : L"OFF");
            SetWindowTextW(g_lblNow, buf);
        }
        return 0;
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDC_BTNSTART) OnStart();
        else if (id == IDC_BTNSET) ApplyFpsFromUI();
        else if (id == IDC_EDFPS && HIWORD(wParam) == EN_KILLFOCUS) ApplyFpsFromUI();
        else if (id == IDM_SHOW) RestoreFromTray();
        else if (id == IDM_EXIT) {
            if (g_GameRunning &&
                MessageBoxW(hwnd, L"游戏正在运行，退出后帧率将恢复 60。确定退出？",
                    L"确认", MB_YESNO | MB_ICONQUESTION) == IDNO) return 0;
            DestroyWindow(hwnd);
        }
        return 0;
    }
    case WMU_FPS:
        SetDlgItemInt(hwnd, IDC_EDFPS, (int)lParam, FALSE);
        return 0;
    case WMU_STATE:
        EnableWindow(g_btnStart, wParam == 0);
        return 0;
    case WMU_TRAY: {
        UINT ev = (UINT)lParam;
        if (ev == WM_LBUTTONDBLCLK) RestoreFromTray();
        else if (ev == WM_RBUTTONUP) {
            POINT pt;
            GetCursorPos(&pt);
            SetForegroundWindow(hwnd);
            HMENU menu = CreatePopupMenu();
            AppendMenuW(menu, MF_STRING, IDM_SHOW, L"显示窗口");
            AppendMenuW(menu, MF_STRING, IDM_EXIT, L"退出");
            TrackPopupMenu(menu, TPM_RIGHTALIGN | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, nullptr);
            DestroyMenu(menu);
        }
        return 0;
    }
    case WM_SYSCOMMAND:
        if (wParam == SC_MINIMIZE) { HideToTray(); return 0; }
        break;
    case WM_CLOSE:
        HideToTray();
        return 0;
    case WM_DESTROY:
        RestoreFpsOnExit();
        TrayRemove();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int main()
{
    g_inst = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = g_inst;
    wc.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(IDI_APPLICATION));
    wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(IDC_ARROW));
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"UnlockFpsGui";
    if (!RegisterClassW(&wc)) return 0;

    g_hwnd = CreateWindowW(wc.lpszClassName, L"原神 FPS 解锁器",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 496, 520, nullptr, nullptr, g_inst, nullptr);
    if (!g_hwnd) return 0;

    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
