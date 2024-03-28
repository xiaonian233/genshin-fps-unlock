#define KEY_TOGGLE VK_END
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
#include <Psapi.h>
#include "inireader.h"

std::string GamePath{};
int FpsValue = FPS_TARGET;

// 特征搜索 - 不是我写的 - 忘了在哪拷的
uintptr_t PatternScan(void* module, const char* signature)
{
    static auto pattern_to_byte = [](const char* pattern) {
        auto bytes = std::vector<uint8_t>{};
        auto start = const_cast<char*>(pattern);
        auto end = const_cast<char*>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            }
            else {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
    };

    auto dosHeader = (PIMAGE_DOS_HEADER)module;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);

    auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    auto patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

    auto s = patternBytes.size();
    auto d = patternBytes.data();

    for (auto i = 0ul; i < sizeOfImage - s; ++i) {
        bool found = true;
        for (auto j = 0ul; j < s; ++j) {
            if (scanBytes[i + j] != d[j] && d[j] != -1) {
                found = false;
                break;
            }
        }
        if (found) {
            return (uintptr_t)&scanBytes[i];
        }
    }
    return 0;
}

std::string GetLastErrorAsString(DWORD code)
{
    LPSTR buf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);
    std::string ret = buf;
    LocalFree(buf);
    return ret;
}

// 获取目标进程DLL信息
bool GetModule(DWORD pid, std::string ModuleName, PMODULEENTRY32 pEntry)
{
    if (!pEntry)
        return false;

    MODULEENTRY32 mod32{};
    mod32.dwSize = sizeof(mod32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    for (Module32First(snap, &mod32); Module32Next(snap, &mod32);)
    {
        if (mod32.th32ProcessID != pid)
            continue;

        if (mod32.szModule == ModuleName)
        {
            *pEntry = mod32;
            break;
        }
    }
    CloseHandle(snap);

    return pEntry->modBaseAddr;
}

// 通过进程名搜索进程ID
DWORD GetPID(std::string ProcessName)
{
    DWORD pid = 0;
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(pe32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    for (Process32First(snap, &pe32); Process32Next(snap, &pe32);)
    {
        if (pe32.szExeFile == ProcessName)
        {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    CloseHandle(snap);
    return pid;
}

bool WriteConfig(std::string GamePath, int fps)
{
    HANDLE hFile = CreateFileA("fps_config.ini", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD code = GetLastError();
        printf("CreateFileA failed (%d): %s\n", code, GetLastErrorAsString(code).c_str());
        return false;
    }

    std::string content{};
    content = "[Setting]\n";
    content += "Path=" + GamePath + "\n";
    content += "FPS=" + std::to_string(fps);

    DWORD written = 0;
    WriteFile(hFile, content.data(), content.size(), &written, nullptr);
    CloseHandle(hFile);
}

void LoadConfig()
{
    if (GetFileAttributesA("config") != INVALID_FILE_ATTRIBUTES)
        DeleteFileA("config");

    INIReader reader("fps_config.ini");
    if (reader.ParseError() != 0)
    {
        printf("配置不存在\n请不要关闭此进程 - 然后手动开启游戏\n这只需要进行一次 - 用于获取游戏路经\n");
        printf("\n等待游戏启动...\n");

        DWORD pid = 0;
        while (!(pid = GetPID("YuanShen.exe")) && !(pid = GetPID("GenshinImpact.exe")))
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // 获取进程句柄 - 这权限很低的了 - 不应该获取不了
        // PROCESS_QUERY_LIMITED_INFORMATION - 用于查询进程路经 (K32GetModuleFileNameExA)
        // SYNCHRONIZE - 用于等待进程结束 (WaitForSingleObject)
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
        if (!hProcess)
        {
            DWORD code = GetLastError();
            printf("OpenProcess failed (%d): %s", code, GetLastErrorAsString(code).c_str());
            return;
        }

        char szPath[MAX_PATH]{};
        DWORD length = sizeof(szPath);
        QueryFullProcessImageNameA(hProcess, 0, szPath, &length);

        GamePath = szPath;
        WriteConfig(GamePath, FpsValue);

        HWND hwnd = nullptr;
        while (!(hwnd = FindWindowA("UnityWndClass", nullptr)))
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

        DWORD ExitCode = STILL_ACTIVE;
        while (ExitCode == STILL_ACTIVE)
        {
            SendMessageA(hwnd, WM_CLOSE, 0, 0);
            GetExitCodeProcess(hProcess, &ExitCode);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        // wait for the game to close then continue
        WaitForSingleObject(hProcess, -1);
        CloseHandle(hProcess);

        system("cls");
        return;
    }

    GamePath = reader.Get("Setting", "Path", "");
    FpsValue = reader.GetInteger("Setting", "FPS", FpsValue);

    if (GetFileAttributesA(GamePath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        printf("配置里的游戏路经改变了 - 开始重新配置\n");
        DeleteFileA("config.ini");
        LoadConfig();
    }
}

// 热键线程
DWORD __stdcall Thread1(LPVOID p)
{
    if (!p)
        return 0;

    int* pTargetFPS = (int*)p;
    int fps = *pTargetFPS;
    int prev = fps;
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
        if (GetAsyncKeyState(KEY_DECREASE) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
            fps -= 20;
        if (GetAsyncKeyState(KEY_DECREASE_SMALL) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
            fps -= 2;
        if (GetAsyncKeyState(KEY_INCREASE) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
            fps += 20;
        if (GetAsyncKeyState(KEY_INCREASE_SMALL) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
            fps += 2;
        if (GetAsyncKeyState(KEY_TOGGLE) & 1)
            fps = fps != 60 ? 60 : prev;
        if (prev != fps)
            WriteConfig(GamePath, fps);
        if (fps > 60)
            prev = fps;
        if (fps < 60)
            fps = 60;
        printf("\rFPS: %d - %s    ", fps, fps > 60 ? "ON" : "OFF");
        *pTargetFPS = fps;
    }

    return 0;
}

int main(int argc, char** argv)
{
    std::atexit([] {
        system("pause");
    });

    SetConsoleTitleA("");
    
    std::string CommandLine{};
    if (argc > 1)
    {
        for (int i = 1; i < argc; i++)
            CommandLine += argv[i] + std::string(" ");
    }

    // 读取配置
    LoadConfig();
    int TargetFPS = FpsValue;
    std::string ProcessPath = GamePath;
    std::string ProcessDir{};

    if (ProcessPath.length() < 8)
        return 0;

    printf("FPS 解锁器 v1.4.2\n");
    printf("游戏路经: %s\n\n", ProcessPath.c_str());
    ProcessDir = ProcessPath.substr(0, ProcessPath.find_last_of("\\"));

    DWORD pid = GetPID(ProcessPath.substr(ProcessPath.find_last_of("\\") + 1));
    if (pid)
    {
        printf("检测到游戏已在运行！\n");
        printf("手动启动游戏会导致失效的\n");
        printf("请手动关闭游戏 - 解锁器会自动启动游戏\n");
        return 0;
    }

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(ProcessPath.c_str(), (LPSTR)CommandLine.c_str(), nullptr, nullptr, FALSE, 0, nullptr, ProcessDir.c_str(), &si, &pi))
    {
        DWORD code = GetLastError();
        printf("CreateProcess failed (%d): %s", code, GetLastErrorAsString(code).c_str());
        return 0;
    }

    CloseHandle(pi.hThread);
    printf("PID: %d\n", pi.dwProcessId);

    // 等待UnityPlayer.dll加载和获取DLL信息
    MODULEENTRY32 hUnityPlayer{};
    MODULEENTRY32 hUserAssembly{};
    while (!GetModule(pi.dwProcessId, "UnityPlayer.dll", &hUnityPlayer))
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    while (!GetModule(pi.dwProcessId, "UserAssembly.dll", &hUserAssembly))
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    printf("UnityPlayer: %p%p\n",  reinterpret_cast<void*>((uintptr_t)hUnityPlayer.modBaseAddr >> 32 & -1), (void*)hUnityPlayer.modBaseAddr);
    printf("UserAssembly: %p%p\n", reinterpret_cast<void*>((uintptr_t)hUnityPlayer.modBaseAddr >> 32 & -1), (void*)hUserAssembly.modBaseAddr);

    // 在本进程内申请UnityPlayer.dll大小的内存 - 用于特征搜索
    //LPVOID mem = VirtualAlloc(nullptr, hUnityPlayer.modBaseSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    LPVOID up = VirtualAlloc(nullptr, hUnityPlayer.modBaseSize + hUserAssembly.modBaseSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!up)
    {
        DWORD code = GetLastError();
        printf("VirtualAlloc failed (%d): %s", code, GetLastErrorAsString(code).c_str());
        return 0;
    }

    // 把整个模块读出来
    if (hUnityPlayer.modBaseAddr == nullptr || hUserAssembly.modBaseAddr == nullptr) {
        printf("invalid module base address: %p: %p\n", reinterpret_cast<void*>(hUnityPlayer.modBaseAddr), reinterpret_cast<void*>(hUserAssembly.modBaseAddr));
        return 0;
    }

    ReadProcessMemory(pi.hProcess, hUnityPlayer.modBaseAddr, up, hUnityPlayer.modBaseSize, nullptr);
    LPVOID ua = (LPVOID)((uintptr_t)up + hUnityPlayer.modBaseSize);
    ReadProcessMemory(pi.hProcess, hUserAssembly.modBaseAddr, ua, hUserAssembly.modBaseSize, nullptr);
    printf("Searching for pattern...\n");

    uintptr_t address = PatternScan(ua, "B9 3C 00 00 00 FF 15");
    if (!address)
    {
        printf("outdated pattern\n");
        return 0;
    }

    // 计算相对地址 (FPS)
    uintptr_t pfps = 0;
    {
        uintptr_t rip = address;
        rip += 5;
		rip += *(int32_t*)(rip + 2) + 6;
        uintptr_t ptr = 0;
        uintptr_t data = rip - (uintptr_t)ua + (uintptr_t)hUserAssembly.modBaseAddr;
        while (!ptr)
        {
            ReadProcessMemory(pi.hProcess, (LPCVOID)data, &ptr, sizeof(uintptr_t), nullptr);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        rip = ptr - (uintptr_t)hUnityPlayer.modBaseAddr + (uintptr_t)up;
        while (*(uint8_t*)rip == 0xE8 || *(uint8_t*)rip == 0xE9)
            rip += *(int32_t*)(rip + 1) + 5;
        pfps = rip + *(int32_t*)(rip + 2) + 6;
        pfps -= (uintptr_t)up;
        printf("FPS Offset: %p\n", (void*)pfps);
        pfps = (uintptr_t)hUnityPlayer.modBaseAddr + pfps;
    }

    // 计算相对地址 (垂直同步)
    address = PatternScan(up, "E8 ? ? ? ? 8B E8 49 8B 1E");
    uintptr_t pvsync = 0;
    if (address)
    {
        uintptr_t ppvsync = 0;
        uintptr_t rip = address;
        int32_t rel = *(int32_t*)(rip + 1);
        rip = rip + rel + 5;
        uint64_t rax = *(uint32_t*)(rip + 3);
        ppvsync = rip + rax + 7;
        ppvsync -= (uintptr_t)up;
        printf("VSync Offset: %p\n", (void*)ppvsync);
        ppvsync = (uintptr_t)hUnityPlayer.modBaseAddr + ppvsync;

        uintptr_t buffer = 0;
        while (!buffer)
        {
            ReadProcessMemory(pi.hProcess, (LPCVOID)ppvsync, &buffer, sizeof(buffer), nullptr);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        rip += 7;
        pvsync = *(uint32_t*)(rip + 2);
        pvsync = buffer + pvsync;
    }

    VirtualFree(up, 0, MEM_RELEASE);
    printf("Done\n\n");
    printf("用右ctrl + 箭头键更改限制:\n");
    printf("  右ctrl + 上: +20\n");
    printf("  右ctrl + 下: -20\n");
    printf("  右ctrl + 左: -2\n");
    printf("  右ctrl + 右: +2\n\n");

    // 创建热键线程
    HANDLE hThread = CreateThread(nullptr, 0, Thread1, &TargetFPS, 0, nullptr);
    if (hThread)
        CloseHandle(hThread);

    DWORD dwExitCode = STILL_ACTIVE;
    while (dwExitCode == STILL_ACTIVE)
    {
        GetExitCodeProcess(pi.hProcess, &dwExitCode);

        // 每两秒检查一次
        std::this_thread::sleep_for(std::chrono::seconds(2));
        int fps = 0;
        ReadProcessMemory(pi.hProcess, (LPVOID)pfps, &fps, sizeof(fps), nullptr);
        if (fps == -1)
            continue;
        if (fps != TargetFPS)
            WriteProcessMemory(pi.hProcess, (LPVOID)pfps, &TargetFPS, sizeof(TargetFPS), nullptr);

        int vsync = 0;
        ReadProcessMemory(pi.hProcess, (LPVOID)pvsync, &vsync, sizeof(vsync), nullptr);
        if (vsync)
        {
            vsync = 0;
            // 关闭垂直同步
            WriteProcessMemory(pi.hProcess, (LPVOID)pvsync, &vsync, sizeof(vsync), nullptr);
        }
    }

    CloseHandle(pi.hProcess);
    TerminateProcess((HANDLE)-1, 0);

    return 0;
}
