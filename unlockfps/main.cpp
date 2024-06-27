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

DWORD StartPriority = 0;
const std::vector<DWORD> PrioityClass = {
   REALTIME_PRIORITY_CLASS,
   HIGH_PRIORITY_CLASS,
   ABOVE_NORMAL_PRIORITY_CLASS,
   NORMAL_PRIORITY_CLASS,
   BELOW_NORMAL_PRIORITY_CLASS,
   IDLE_PRIORITY_CLASS
};
//credit by winTEuser
BYTE _shellcode_genshin[] =
{
    0x00, 0x00, 0x00, 0x00, // DWORD unlocker_pid                                       _shellcode_genshin[0]
    0x00, 0x00, 0x00, 0x00, // DWORD unlocker_Handle                                    _shellcode_genshin[4]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //DWORD64 unlocker_FpsValue_addr    _shellcode_genshin[8]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //DWORD64 API_OpenProcess           _shellcode_genshin[16]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //DWORD64 API_ReadProcessmem        _shellcode_genshin[24]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //DWORD64 API_Sleep                 _shellcode_genshin[32]
    0x00, 0x00, 0x00, 0x00, //uint32_t Readmem_buffer                                   _shellcode_genshin[40]
    0xCC, 0xCC, 0xCC, 0xCC, //int3
    0x48, 0x83, 0xEC, 0x38,                 //sub rsp,0x38                              _shellcode_genshin[48] _sync_thread
    0x8B, 0x05, 0xC6, 0xFF, 0xFF, 0xFF,     //mov eax,dword[unlocker_pid]
    0x85, 0xC0,                             //test eax
    0x74, 0x49,                             //je return
    0x41, 0x89, 0xC0,                       //mov r8d,eax
    0x33, 0xD2,                             //xor edx,edx
    0xB9, 0xFF, 0xFF, 0x1F, 0x00,           //mov ecx,1FFFFF
    0xFF, 0x15, 0xC2, 0xFF, 0xFF, 0xFF,     //call [API_OpenProcess]
    0x85, 0xC0,                             //test eax
    0x74, 0x35,                             //je return
    0x89, 0x05, 0xAC, 0xFF, 0xFF, 0xFF,     //mov dword[unlocker_Handle],eax
    0x89, 0xC6,                             //mov esi,eax
    0x48, 0x8B, 0x3D, 0xA7, 0xFF, 0xFF, 0xFF, //mov rdi,qword[unlocker_FpsValue_addr]
    0x0F, 0x1F, 0x00,                       //nop
    0x89, 0xF1,                             //mov ecx,esi   //Read_tar_fps
    0x48, 0x89, 0xFA,                       //mov rdx,rdi
    0x4C, 0x8D, 0x05, 0xB8, 0xFF, 0xFF, 0xFF,//lea r8,qword[Readmem_buffer]
    0x41, 0xB9, 0x04, 0x00, 0x00, 0x00,     //mov r9d,4
    0x31, 0xC0,                             //xor eax,eax
    0x48, 0x89, 0x44, 0x24, 0x20,           //mov qword ptr ss:[rsp+20],rax
    0xFF, 0x15, 0x95, 0xFF, 0xFF, 0xFF,     //call [API_ReadProcessmem]
    0x85, 0xC0,                             //test eax
    0x75, 0x06,                             //jne sleep
    0x48, 0x83, 0xC4, 0x38,                 //add rsp,0x38  //return
    0xC3,                                   //ret
    0xCC,                                   //int3
    0xB9, 0xE8, 0x03, 0x00, 0x00,           //mov ecx,0x3e8 //(1000ms) sleep        
    0xFF, 0x15, 0x88, 0xFF, 0xFF, 0xFF,     //call [API_Sleep]
    0xEB, 0xCA,                             //jmp Read_tar_fps
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,     //int3
    0x83, 0xF9, 0x1E,                       //cmp ecx,0x1E                      //hook_fps_set      _shellcode_genshin[160]
    0x74, 0x14,                             //je set 60
    0x83, 0xF9, 0x2D,                       //cmp ecx,0x2D
    0x74, 0x07,                             //je set tar_fps
    0xB9, 0xFF, 0xFF, 0xFF, 0xFF,           //mov ecx, -1 //default set unlimited
    0xEB, 0x0D,                             //jmp set
    0x8B, 0x0D, 0x71, 0xFF, 0xFF, 0xFF,     //mov ecx,[Readmem_buffer]
    0xEB, 0x05,                             //jmp set
    0xB9, 0x3C, 0x00, 0x00, 0x00,           //mov ecx,0x3C
    0x89, 0x0D, 0x0D, 0x00, 0x00, 0x00,     //mov [hook_set],ecx
    0xC3,                                   //ret
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //int3
    0xB8,0x78, 0x00, 0x00, 0x00,            //mov eax,0x78                      //hook_fps_get      _shellcode_genshin[208]
    0xC3,                                   //ret
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC        //int3
};

// 特征搜索 - 不是我写的 - 忘了在哪拷的
uintptr_t PatternScan(void* module, const char* signature)
{
    static auto pattern_to_byte = [](const char* pattern) {
        auto bytes = std::vector<int>{};
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
static uintptr_t PatternScan_Region(uintptr_t startAddress, size_t regionSize, const char* signature)
{
    auto pattern_to_byte = [](const char* pattern)
    {
        std::vector<int> bytes;
        const char* start = pattern;
        const char* end = pattern + strlen(pattern);

        for (const char* current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            }
            else {
                bytes.push_back(strtoul(current, const_cast<char**>(&current), 16));
            }
        }
        return bytes;
    };

    std::vector<int> patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t*>(startAddress);

    for (size_t i = 0; i < regionSize - patternBytes.size(); ++i)
    {
        bool found = true;
        for (size_t j = 0; j < patternBytes.size(); ++j) {
            if (scanBytes[i + j] != patternBytes[j] && patternBytes[j] != -1) {
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

bool GetModule2(HANDLE GameHandle, std::string ModuleName, PMODULEENTRY32 pEntry)
{
    if (!pEntry)
        return false;

    std::vector<HMODULE> modules(1024);
    ZeroMemory(modules.data(), modules.size() * sizeof(HMODULE));
    DWORD cbNeeded = 0;

    if (!EnumProcessModules(GameHandle, modules.data(), modules.size() * sizeof(HMODULE), &cbNeeded))
        return false;

    modules.resize(cbNeeded / sizeof(HMODULE));
    for (auto& it : modules)
    {
        char szModuleName[MAX_PATH]{};
        if (!GetModuleBaseNameA(GameHandle, it, szModuleName, MAX_PATH))
            continue;
        if (ModuleName != szModuleName)
            continue;
        MODULEINFO modInfo{};
        if (!GetModuleInformation(GameHandle, it, &modInfo, sizeof(MODULEINFO)))
            continue;

        pEntry->modBaseAddr = (BYTE*)modInfo.lpBaseOfDll;
        pEntry->modBaseSize = modInfo.SizeOfImage;
        return true;
    }


    return false;
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
//Hotpatch
static DWORD64 inject_patch(LPVOID unity_module, DWORD64 unity_baseaddr, DWORD64 _ptr_fps, HANDLE Tar_handle)
{
    BYTE search_sec[] = ".text";//max 8 byte
    uintptr_t WinPEfileVA = *(uintptr_t*)(&unity_module) + 0x3c; //dos_header
    uintptr_t PEfptr = *(uintptr_t*)(&unity_module) + *(uint32_t*)WinPEfileVA; //get_winPE_VA
    _IMAGE_NT_HEADERS64 _FilePE_Nt_header = *(_IMAGE_NT_HEADERS64*)PEfptr;
    _IMAGE_SECTION_HEADER _sec_temp{};
    DWORD64 Module_TarSec_RVA;
    DWORD64 Module_TarSecEnd_RVA;
    DWORD Module_TarSec_Size;
    if (_FilePE_Nt_header.Signature == 0x00004550)
    {
        DWORD sec_num = _FilePE_Nt_header.FileHeader.NumberOfSections;//获得指定节段参数
        DWORD num = sec_num;
        while (num)
        {
            _sec_temp = *(_IMAGE_SECTION_HEADER*)(PEfptr + 264 + (40 * (static_cast<unsigned long long>(sec_num) - num)));

            //printf_s("sec_%d_is:  %s\n", sec_num - num, _sec_temp.Name);
            int i = 8;
            int len = sizeof(search_sec) - 1;
            int cmp = 0;
            while ((i != 0) && _sec_temp.Name[8 - i] && search_sec[8 - i])
            {
                if (_sec_temp.Name[8 - i] == search_sec[8 - i])
                {
                    cmp++;
                }
                i--;
            }
            if (cmp == len)
            {
                Module_TarSec_RVA = _sec_temp.VirtualAddress + (DWORD64)unity_module;
                Module_TarSec_Size = _sec_temp.Misc.VirtualSize;
                Module_TarSecEnd_RVA = Module_TarSec_RVA + Module_TarSec_Size;
                goto __Get_target_sec;
            }
            num--;
        }
        printf_s("Get Target Section Fail !\n");
        return 0;
    }
    return 0;

__Get_target_sec:
    DWORD64 address = 0;
    {
        DWORD64 Hook_addr_fpsget = 0;   //in buffer
        DWORD64 Hook_addr_tar_fpsget = 0;
        DWORD64 Hook_addr_fpsSet = 0;   //in buffer
        DWORD64 Hook_addr_tar_fpsSet = 0;
        DWORD64 _addr_tar_fpsget_TarFun = 0;
        DWORD64 _addr_tar_fpsSet_TarFun = 0;
        while (address = PatternScan_Region(Module_TarSec_RVA, Module_TarSec_Size, "CC 8B 05 ?? ?? ?? ?? C3 CC"))//搜索正确patch点位//get_fps
        {
            uintptr_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip)+4;
            if ((rip - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr) == _ptr_fps)
            {
                Hook_addr_fpsget = address + 1;
                Hook_addr_tar_fpsget = Hook_addr_fpsget - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr;
                goto __Get_fpsGet_addr;
            }
            else
            {
                *(uint64_t*)(address + 1) = 0xCCCCCCCCCCCCCCCC;
            }
        }
        printf_s("\nPatch pattern1 outdate...\n");
        return 0;

    __Get_fpsGet_addr:
        while (address = PatternScan_Region(Module_TarSec_RVA, Module_TarSec_Size, "CC 89 0D ?? ?? ?? ?? C3 CC"))//搜索正确patch点位//set_fps
        {
            uintptr_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip)+4;
            if ((rip - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr) == _ptr_fps)
            {
                Hook_addr_fpsSet = address + 1;
                Hook_addr_tar_fpsSet = Hook_addr_fpsSet - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr;
                goto __Get_fpsSet_addr;
            }
            else
            {
                *(uint64_t*)(address + 1) = 0xCCCCCCCCCCCCCCCC;
            }
        }
        printf_s("\nPatch pattern2 outdate...\n");
        return 0;

    __Get_fpsSet_addr:
        uint64_t _Addr_OpenProcess = 0;
        uint64_t _Addr_ReadProcessmem = 0;
        uint64_t _Addr_Sleep = 0;
        if (address = PatternScan_Region(Module_TarSec_RVA, Module_TarSec_Size, "33 D2 B9 00 04 00 00 FF 15 ?? ?? ?? ??"))//get API OpenProcess
        {
            uintptr_t rip = address;
            rip += 9;
            rip += *(int32_t*)(rip)+4;
            if (*(uint64_t*)(rip) == 0)
            {
                rip = rip - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr;
                while (_Addr_OpenProcess == 0)
                {
                    if (ReadProcessMemory(Tar_handle, (LPCVOID)rip, &_Addr_OpenProcess, 8, 0) == 0)
                    {
                        DWORD ERR_code = GetLastError();
                        printf_s("\nGet Target Openprocess API Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
                        return 0;
                    }
                }
            }
            else { _Addr_OpenProcess = *(uint64_t*)rip; }
        }
        if (address = PatternScan_Region(Module_TarSec_RVA, Module_TarSec_Size, "48 89 44 24 20 FF 15 ?? ?? ?? ?? 48 8B 54 24 70"))//get API ReadProcmem
        {
            uintptr_t rip = address;
            rip += 7;
            rip += *(int32_t*)(rip)+4;
            if (*(uint64_t*)(rip) == 0)
            {
                rip = rip - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr;
                while (_Addr_ReadProcessmem == 0)
                {
                    if (ReadProcessMemory(Tar_handle, (LPCVOID)rip, &_Addr_ReadProcessmem, 8, 0) == 0)
                    {
                        DWORD ERR_code = GetLastError();
                        printf_s("\nGet Target Readprocmem API Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
                        return 0;
                    }
                }
            }
            else { _Addr_ReadProcessmem = *(uint64_t*)rip; }
        }
        if (address = PatternScan_Region(Module_TarSec_RVA, Module_TarSec_Size, "41 8B C8 FF 15 ?? ?? ?? ?? 8B C7"))//get API Sleep
        {
            uintptr_t rip = address;
            rip += 5;
            rip += *(int32_t*)(rip)+4;
            if (*(uint64_t*)(rip) == 0)
            {
                rip = rip - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr;
                while (_Addr_Sleep == 0)
                {
                    if (ReadProcessMemory(Tar_handle, (LPCVOID)rip, &_Addr_Sleep, 8, 0) == 0)
                    {
                        DWORD ERR_code = GetLastError();
                        printf_s("\nGet Target Sleep API Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
                        return 0;
                    }
                }
            }
            else { _Addr_Sleep = *(uint64_t*)rip; }
        }
        *(uint32_t*)(&_shellcode_genshin) = GetCurrentProcessId();    //unlocker PID
        *(uint64_t*)(&_shellcode_genshin[8]) = (uint64_t)(&FpsValue); //unlocker fps set
        *(uint64_t*)(&_shellcode_genshin[16]) = _Addr_OpenProcess;
        *(uint64_t*)(&_shellcode_genshin[24]) = _Addr_ReadProcessmem;
        *(uint64_t*)(&_shellcode_genshin[32]) = _Addr_Sleep;
        LPVOID __Tar_proc_buffer = VirtualAllocEx(Tar_handle, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (__Tar_proc_buffer)
        {
            if (WriteProcessMemory(Tar_handle, __Tar_proc_buffer, &_shellcode_genshin, sizeof(_shellcode_genshin), 0));
            {
                _addr_tar_fpsSet_TarFun = (uint64_t)__Tar_proc_buffer + 160;
                _addr_tar_fpsget_TarFun = (uint64_t)__Tar_proc_buffer + 208;
                *(uint64_t*)Hook_addr_fpsget = 0xCCCCCCCCCCCCCCCC;
                *(uint64_t*)Hook_addr_fpsSet = 0xCCCCCCCCCCCCCCCC;
                *(uint64_t*)Hook_addr_fpsget = 0x25FF;
                *(uint64_t*)(Hook_addr_fpsget + 6) = _addr_tar_fpsget_TarFun;
                *(uint64_t*)Hook_addr_fpsSet = 0x25FF;
                *(uint64_t*)(Hook_addr_fpsSet + 6) = _addr_tar_fpsSet_TarFun;
                if (WriteProcessMemory(Tar_handle, (LPVOID)Hook_addr_tar_fpsget, (LPVOID)Hook_addr_fpsget, 0x10, 0) == 0)
                {
                    DWORD ERR_code = GetLastError();
                    printf_s("\nHook get_fps Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
                }
                if (WriteProcessMemory(Tar_handle, (LPVOID)Hook_addr_tar_fpsSet, (LPVOID)Hook_addr_fpsSet, 0x10, 0) == 0)
                {
                    DWORD ERR_code = GetLastError();
                    printf_s("\nHook get_fps Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
                }
                HANDLE temp = CreateRemoteThread(Tar_handle, 0, 0, (LPTHREAD_START_ROUTINE)((uint64_t)__Tar_proc_buffer + 0x30), 0, 0, 0);
                if (temp)
                {
                    CloseHandle(temp);
                }
                return ((uint64_t)__Tar_proc_buffer + 0xD1);
            }
            DWORD ERR_code = GetLastError();
            printf_s("\nWrite Patch Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
        }
        else
        {
            DWORD ERR_code = GetLastError();
            printf_s("\nVirtual Alloc Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
            return 0;
        }
    }
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
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, FALSE, pid);
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

    printf("FPS解锁 好用的话点个star吧\n");
    printf("https://github.com/xiaonian233/genshin-fps-unlock \n4.7版本特别感谢winTEuser老哥支持 \n");
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
    StartPriority = PrioityClass[1];
    SetPriorityClass(pi.hProcess, StartPriority);

    // 等待UnityPlayer.dll加载和获取DLL信息
    MODULEENTRY32 hUnityPlayer{};
    while (!GetModule2(pi.hProcess, "UnityPlayer.dll", &hUnityPlayer))
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    printf("UnityPlayer: %X%X\n", (uintptr_t)hUnityPlayer.modBaseAddr >> 32 & -1, hUnityPlayer.modBaseAddr);


    // 在本进程内申请UnityPlayer.dll大小的内存 - 用于特征搜索
    LPVOID up = VirtualAlloc(nullptr, hUnityPlayer.modBaseSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!up)
    {
        DWORD code = GetLastError();
        printf("VirtualAlloc UP failed (%d): %s", code, GetLastErrorAsString(code).c_str());
        return 0;
    }

    // 把整个模块读出来
    if (!ReadProcessMemory(pi.hProcess, hUnityPlayer.modBaseAddr, up, hUnityPlayer.modBaseSize, nullptr))
    {
        DWORD code = GetLastError();
        printf("ReadProcessMemory unity failed (%d): %s", code, GetLastErrorAsString(code).c_str());
        return 0;
    }


    printf("Searching for pattern...\n");

	//credit by winTEuser
	
    uintptr_t address = PatternScan(up, "7F 0E E8 ?? ?? ?? ?? 66 0F 6E C8"); // ver 3.7 - last 
    if (!address)
    {
            printf("outdated pattern\n");
            return 0;
    }

    // 计算相对地址 (FPS)
    uintptr_t pfps = 0;
    {
        uintptr_t rip = address;
        rip += 3;
        rip += *(int32_t*)(rip)+6;
        rip += *(int32_t*)(rip)+4;
        pfps = rip - (uintptr_t)up + (uintptr_t)hUnityPlayer.modBaseAddr;
        printf("FPS Offset: %X\n", pfps);
    }
    uintptr_t Patch_ptr = 0;
    {
        Patch_ptr = inject_patch(up, (DWORD64)hUnityPlayer.modBaseAddr, pfps, pi.hProcess);//45 patch config
        if (Patch_ptr == NULL)
        {
            printf_s("Inject Patch Fail!\n\n");
        }
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


    }

    CloseHandle(pi.hProcess);
    TerminateProcess((HANDLE)-1, 0);

    return 0;
}
