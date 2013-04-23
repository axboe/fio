@echo off
setlocal enabledelayedexpansion
set /a counter=1
for /f "tokens=3" %%i in (..\..\FIO-VERSION-FILE) do (
 if "!counter!"=="1" set FIO_VERSION=%%i
 set /a counter+=1
)

if "%1"=="x86" set FIO_ARCH=x86
if "%1"=="x64" set FIO_ARCH=x64

if not defined FIO_ARCH (
  echo Error: must specify the architecture.
  echo Usage: dobuild x86
  echo Usage: dobuild x64
  goto end
)

"%WIX%bin\candle" -nologo -arch %FIO_ARCH% install.wxs
@if ERRORLEVEL 1 goto end
"%WIX%bin\candle" -nologo -arch %FIO_ARCH% examples.wxs
@if ERRORLEVEL 1 goto end
"%WIX%bin\light" -nologo -sice:ICE61 install.wixobj examples.wixobj -ext WixUIExtension -out %FIO_VERSION%-%FIO_ARCH%.msi
:end
