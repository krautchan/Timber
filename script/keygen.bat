@echo off

set KEYSIZE=512
set CONFIG=none

goto start

:genkey

echo Generating %KEYSIZE%-bit keys...
cd include
..\%CONFIG%\keygen.exe %KEYSIZE%
echo done.

goto end

:start

if exist Debug\keygen.exe set CONFIG=Debug
if exist Release\keygen.exe set CONFIG=Release

if %CONFIG%==none exit

echo Detected configuration %CONFIG%

if not exist include\server_key.h goto genkey
echo Keys already exist.

:end