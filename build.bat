@echo off
call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

cd /d "%~dp0"

echo === Compiling MyPlugin (multi-file) ===
cl /nologo /EHsc /O2 /MD /LD /std:c++17 /source-charset:utf-8 /I"D:\soft\x64dbg" plugin.cpp call_scanner.cpp memsearch.cpp structview.cpp /link /OUT:MyPlugin.dp64 /DLL "D:\soft\x64dbg\pluginsdk\x64dbg.lib" "D:\soft\x64dbg\pluginsdk\x64bridge.lib" user32.lib comctl32.lib gdi32.lib shlwapi.lib
if errorlevel 1 goto :error

echo === Build successful! ===
copy /Y MyPlugin.dp64 "D:\soft\x64dbg\release\x64\plugins\MyPlugin.dp64"
echo === Deployed to plugins directory ===
goto :end

:error
echo === Build FAILED ===
exit /b 1

:end
