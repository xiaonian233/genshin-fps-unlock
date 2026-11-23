@echo off
rem 一键编译 GUI 版（自动探测 Visual Studio / Build Tools 的 MSBuild）
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo 未找到 vswhere，请安装 Visual Studio 2019/2022 或 Build Tools
    pause
    exit /b 1
)
set "MSBUILD="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set "MSBUILD=%%i"
if not defined MSBUILD (
    echo 未找到 MSBuild，请安装 Visual Studio 2019/2022 ^(含 C++ 工作负荷^)
    pause
    exit /b 1
)
"%MSBUILD%" unlockfps-gui\unlockfps-gui.vcxproj /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
if %ERRORLEVEL%==0 (
    copy /y unlockfps-gui\x64\Release\unlockfps-gui.exe unlockfps-gui.exe
) else (
    echo 编译失败
)
pause
