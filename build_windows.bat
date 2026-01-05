@echo off
setlocal
echo Building sn_tool.exe with MSVC...
cl /nologo /O2 /EHsc sn_tool.cpp /link Crypt32.lib /out:sn_tool.exe
if exist sn_tool.exe (
  echo Build succeeded: sn_tool.exe
  goto :done
) else (
  echo MSVC build failed. Trying MinGW if available...
)

where g++ >nul 2>nul
if %ERRORLEVEL%==0 (
  g++ -O2 sn_tool.cpp -lcrypt32 -o sn_tool.exe
)

:done
endlocal
