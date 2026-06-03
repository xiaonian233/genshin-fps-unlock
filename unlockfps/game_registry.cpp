#include "game_registry.h"

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <vector>

namespace
{
    constexpr const char* kHdrOnValueName = "WINDOWS_HDR_ON_h3132281285";
    constexpr const char* kGeneralDataValueName = "GENERAL_DATA_h2389025596";
    constexpr const char* kGlobalSubKey = "Software\\miHoYo\\Genshin Impact";
    constexpr const char* kCnSubKey = "Software\\miHoYo\\\xe5\x8e\x9f\xe7\xa5\x9e"; // 原神

    std::wstring Utf8ToWide(const std::string& utf8)
    {
        if (utf8.empty())
            return {};

        const int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), nullptr, 0);
        if (len <= 0)
            return {};

        std::wstring wide(static_cast<size_t>(len), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), wide.data(), len);
        return wide;
    }

    std::string GetExeFileName(const std::string& gameExePath)
    {
        const size_t pos = gameExePath.find_last_of("\\/");
        if (pos == std::string::npos)
            return gameExePath;
        return gameExePath.substr(pos + 1);
    }

    bool EqualsIgnoreCase(const std::string& a, const std::string& b)
    {
        if (a.size() != b.size())
            return false;
        for (size_t i = 0; i < a.size(); ++i)
        {
            if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
                return false;
        }
        return true;
    }

    bool RegGetBinary(HKEY key, const wchar_t* valueName, std::vector<BYTE>* out)
    {
        DWORD type = 0;
        DWORD size = 0;
        const LONG query = RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &size);
        if (query == ERROR_FILE_NOT_FOUND)
        {
            out->clear();
            return true;
        }
        if (query != ERROR_SUCCESS || type != REG_BINARY || size == 0)
            return false;

        out->resize(size);
        return RegQueryValueExW(key, valueName, nullptr, &type, out->data(), &size) == ERROR_SUCCESS;
    }

    bool RegSetBinary(HKEY key, const wchar_t* valueName, const std::vector<BYTE>& data)
    {
        return RegSetValueExW(
                   key,
                   valueName,
                   0,
                   REG_BINARY,
                   data.empty() ? nullptr : data.data(),
                   static_cast<DWORD>(data.size())) == ERROR_SUCCESS;
    }

    bool RegSetDword(HKEY key, const wchar_t* valueName, DWORD value)
    {
        return RegSetValueExW(key, valueName, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value)) == ERROR_SUCCESS;
    }

    std::string TrimJsonPadding(const std::vector<BYTE>& data)
    {
        if (data.empty())
            return {};

        size_t end = data.size();
        while (end > 0 && data[end - 1] == 0)
            --end;

        return std::string(reinterpret_cast<const char*>(data.data()), end);
    }

    bool TryReplaceJsonNumber(std::string& json, const std::string& key, int value)
    {
        const std::string quoted = "\"" + key + "\"";
        const size_t keyPos = json.find(quoted);
        if (keyPos == std::string::npos)
            return false;

        size_t colon = json.find(':', keyPos + quoted.size());
        if (colon == std::string::npos)
            return false;

        size_t i = colon + 1;
        while (i < json.size() && (json[i] == ' ' || json[i] == '\t' || json[i] == '\r' || json[i] == '\n'))
            ++i;

        const size_t start = i;
        if (i < json.size() && (json[i] == '-' || json[i] == '+'))
            ++i;

        bool hasDigit = false;
        while (i < json.size() && (std::isdigit(static_cast<unsigned char>(json[i])) || json[i] == '.'))
        {
            hasDigit = true;
            ++i;
        }
        if (!hasDigit)
            return false;

        json.replace(start, i - start, std::to_string(value));
        return true;
    }

    void InsertJsonField(std::string& json, const std::string& key, int value)
    {
        const std::string field = "\"" + key + "\":" + std::to_string(value);
        const size_t close = json.rfind('}');
        if (close == std::string::npos || json.find('{') == std::string::npos)
        {
            json = "{" + field + "}";
            return;
        }

        size_t pos = close;
        while (pos > 0 && (json[pos - 1] == ' ' || json[pos - 1] == '\t' || json[pos - 1] == '\r' || json[pos - 1] == '\n'))
            --pos;

        const bool hasContent = json.find_first_not_of(" \t\r\n{", 0) < pos;
        if (hasContent)
            json.insert(pos, "," + field);
        else
            json.insert(pos, field);
    }

    void EnsureJsonField(std::string& json, const std::string& key, int value)
    {
        if (!TryReplaceJsonNumber(json, key, value))
            InsertJsonField(json, key, value);
    }

    std::string BuildGeneralDataJson(int maxLuminance, int sceneLuminance, int uiLuminance, const std::vector<BYTE>& existing)
    {
        std::string json = TrimJsonPadding(existing);
        if (json.empty())
        {
            return "{\"maxLuminosity\":" + std::to_string(maxLuminance) +
                   ",\"scenePaperWhite\":" + std::to_string(sceneLuminance) +
                   ",\"uiPaperWhite\":" + std::to_string(uiLuminance) + "}";
        }

        EnsureJsonField(json, "maxLuminosity", maxLuminance);
        EnsureJsonField(json, "scenePaperWhite", sceneLuminance);
        EnsureJsonField(json, "uiPaperWhite", uiLuminance);
        return json;
    }

    std::vector<BYTE> EncodeGeneralDataBlob(const std::string& json)
    {
        std::vector<BYTE> blob(json.begin(), json.end());
        blob.push_back(0);
        return blob;
    }
}

GenshinHdrSettings ClampGenshinHdrSettings(GenshinHdrSettings settings)
{
    settings.maxLuminance = std::clamp(settings.maxLuminance, 300, 2000);
    settings.sceneLuminance = std::clamp(settings.sceneLuminance, 100, 500);
    settings.uiLuminance = std::clamp(settings.uiLuminance, 150, 550);
    return settings;
}

std::string GetGenshinRegistrySubKey(const std::string& gameExePath)
{
    const std::string exe = GetExeFileName(gameExePath);
    if (EqualsIgnoreCase(exe, "GenshinImpact.exe"))
        return kGlobalSubKey;
    return kCnSubKey;
}

bool ApplyGenshinHdrSettings(const std::string& gameExePath, const GenshinHdrSettings& settings, std::string* errorOut)
{
    if (errorOut)
        errorOut->clear();

    if (gameExePath.empty())
    {
        if (errorOut)
            *errorOut = "game path is empty";
        return false;
    }

    const GenshinHdrSettings hdr = ClampGenshinHdrSettings(settings);
    const std::wstring subKey = Utf8ToWide(GetGenshinRegistrySubKey(gameExePath));
    const std::wstring hdrOnName = Utf8ToWide(kHdrOnValueName);
    const std::wstring generalDataName = Utf8ToWide(kGeneralDataValueName);

    HKEY key = nullptr;
    LONG openResult = RegOpenKeyExW(HKEY_CURRENT_USER, subKey.c_str(), 0, KEY_READ | KEY_WRITE, &key);
    if (openResult == ERROR_FILE_NOT_FOUND)
    {
        openResult = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subKey.c_str(),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE,
            nullptr,
            &key,
            nullptr);
    }

    if (openResult != ERROR_SUCCESS || !key)
    {
        if (errorOut)
            *errorOut = "failed to open registry key (" + std::to_string(openResult) + ")";
        return false;
    }

    bool ok = true;
    std::string stepError;

    if (!RegSetDword(key, hdrOnName.c_str(), hdr.enable ? 1u : 0u))
    {
        ok = false;
        stepError = "failed to write HDR switch";
    }

    std::vector<BYTE> existing;
    if (ok && !RegGetBinary(key, generalDataName.c_str(), &existing))
    {
        ok = false;
        stepError = "failed to read GENERAL_DATA";
    }

    if (ok)
    {
        const std::string json = BuildGeneralDataJson(hdr.maxLuminance, hdr.sceneLuminance, hdr.uiLuminance, existing);
        const std::vector<BYTE> blob = EncodeGeneralDataBlob(json);
        if (!RegSetBinary(key, generalDataName.c_str(), blob))
        {
            ok = false;
            stepError = "failed to write GENERAL_DATA";
        }
    }

    RegCloseKey(key);

    if (!ok && errorOut)
        *errorOut = stepError;

    return ok;
}
