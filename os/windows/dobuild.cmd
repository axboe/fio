@echo off
setlocal enabledelayedexpansion
set /a counter=1
for /f "tokens=3" %%i in (..\..\FIO-VERSION-FILE) do (
 if "!counter!"=="1" set FIO_VERSION=%%i
 set /a counter+=1
)

for /f "tokens=2 delims=-" %%i in ("%FIO_VERSION%") do (
 set FIO_VERSION_NUMBERS=%%i
)

if not defined FIO_VERSION_NUMBERS (
  echo Could not find version numbers in the string '%FIO_VERSION%'
  echo Expected version to follow format 'fio-^([0-9]+.[0-9.]+^)'
  goto end
)

if "%1"=="x86" set FIO_ARCH=x86
if "%1"=="x64" set FIO_ARCH=x64

if not defined FIO_ARCH (
  echo Error: must specify the architecture.
  echo Usage: dobuild x86
  echo Usage: dobuild x64
  goto end
)

if defined SIGN_FIO (
  signtool sign /n "%SIGNING_CN%" /t http://timestamp.digicert.com ..\..\fio.exe
  signtool sign /as /n "%SIGNING_CN%" /tr http://timestamp.digicert.com /td sha256 /fd sha256 ..\..\fio.exe

  signtool sign /n "%SIGNING_CN%" /t http://timestamp.digicert.com ..\..\t\*.exe
  signtool sign /as /n "%SIGNING_CN%" /tr http://timestamp.digicert.com /td sha256 /fd sha256 ..\..\t\*.exe
)

if exist ..\..\fio.pdb (
  set FIO_PDB=true
) else (
  set FIO_PDB=false
)

"%WIX%bin\candle" -nologo -arch %FIO_ARCH% -dFioVersionNumbers="%FIO_VERSION_NUMBERS%" -dFioPDB="%FIO_PDB%" install.wxs
@if ERRORLEVEL 1 goto end
"%WIX%bin\candle" -nologo -arch %FIO_ARCH% examples.wxs
@if ERRORLEVEL 1 goto end
"%WIX%bin\candle" -nologo -arch %FIO_ARCH% WixUI_Minimal_NoEULA.wxs
@if ERRORLEVEL 1 goto end

"%WIX%bin\light" -nologo -sice:ICE61 install.wixobj examples.wixobj WixUI_Minimal_NoEULA.wixobj -loc WixUI_fio.wxl -ext WixUIExtension -out %FIO_VERSION%-%FIO_ARCH%.msi
:end

if defined SIGN_FIO (
  signtool sign /n "%SIGNING_CN%" /tr http://timestamp.digicert.com /td sha256 /fd sha256 %FIO_VERSION%-%FIO_ARCH%.msi
)
