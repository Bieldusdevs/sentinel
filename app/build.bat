@echo off
rem Compila o Sentinel.exe (app nativo Win32 + WebView2) com o MSVC Build Tools 2022.
rem Uso: duplo clique, ou  app\build.bat  a partir da pasta do projeto.
setlocal
set ROOT=%~dp0..
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARS%" (
  echo [ERRO] Nao achei o vcvars64.bat do Visual Studio Build Tools 2022.
  echo        Instale o workload "Desenvolvimento para desktop com C++".
  exit /b 1
)
call "%VCVARS%" >nul
echo Compilando Sentinel.exe ...
cl /nologo /std:c++17 /EHsc /O2 /DUNICODE /D_UNICODE /DNDEBUG ^
   /I "%~dp0webview2\include" ^
   "%~dp0sentinel.cpp" ^
   /Fe:"%ROOT%\Sentinel.exe" /Fo:"%~dp0sentinel.obj" ^
   /link /SUBSYSTEM:WINDOWS /MANIFEST:EMBED /MANIFESTINPUT:"%~dp0app.manifest" ^
   "%~dp0webview2\lib\WebView2LoaderStatic.lib"
if errorlevel 1 ( echo [ERRO] Falha na compilacao. & exit /b 1 )
del "%~dp0sentinel.obj" 2>nul
echo.
echo OK: %ROOT%\Sentinel.exe
endlocal
