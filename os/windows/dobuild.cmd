@echo off
setlocal enabledelayedexpansion
set /a counter=4
for /f "tokens=3" %%i in (..\..\fio_version.h) do (
 if "!counter!"=="4" set FIO_MAJOR=%%i
 if "!counter!"=="5" set FIO_MINOR=%%i
 if "!counter!"=="6" set FIO_PATCH=%%i
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
"%WIX%bin\light" -nologo install.wixobj examples.wixobj -ext WixUIExtension -out fio-%FIO_MAJOR%.%FIO_MINOR%.%FIO_PATCH%-%FIO_ARCH%.msi
:end