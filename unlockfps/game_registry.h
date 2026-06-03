#pragma once

#include <string>

struct GenshinHdrSettings
{
    bool enable = false;
    int maxLuminance = 1000;
    int sceneLuminance = 300;
    int uiLuminance = 350;
};

GenshinHdrSettings ClampGenshinHdrSettings(GenshinHdrSettings settings);

// Registry subkey under HKCU, e.g. Software\miHoYo\原神
std::string GetGenshinRegistrySubKey(const std::string& gameExePath);

// Writes WINDOWS_HDR_ON and GENERAL_DATA luminance fields (Starward-compatible).
bool ApplyGenshinHdrSettings(const std::string& gameExePath, const GenshinHdrSettings& settings, std::string* errorOut);
