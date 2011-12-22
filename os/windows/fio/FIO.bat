@echo off

%SYSTEMDRIVE%
IF EXIST     "%PROGRAMFILES(X86)%" set ROOTDIR=%PROGRAMFILES(X86)%\FIO
IF NOT EXIST "%PROGRAMFILES(X86)%" set ROOTDIR=%PROGRAMFILES%\FIO
chdir "%ROOTDIR%\bin"

bash -c "echo \"Run FIO by typing 'fio'\" && echo \"This is a virtual filesystem: the root directory is $ROOTDIR\" && echo \"In this environment the path separator is '/' not '\\'\" && echo \"The C: drive is available under /cygdrive/c\" && echo \"Examples are in /examples ($ROOTDIR\\examples)\" && echo \"Type 'cd' to change directory and 'dir' (or 'ls') to see directory contents\" && echo \"QuickEdit mode is enabled: copy text by highlighting it and right-clicking\" && echo \"To exit, close the window\" && /usr/sbin/cygserver & 2> /dev/null"
bash --login -i
