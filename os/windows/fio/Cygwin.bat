@echo off

C:
IF EXIST     "%PROGRAMFILES(X86)%" chdir "%PROGRAMFILES(X86)%\fio\bin"
IF NOT EXIST "%PROGRAMFILES(X86)%" chdir "%PROGRAMFILES%\fio\bin"

bash -c "echo \"FIO is available as /bin/fio - type fio to run it.\" && echo \"Examples are in /usr/share/doc/fio/examples\" && echo \"Type \"cd\" to change directory and dir (or ls) to see directory contents.\" && echo \"To exit, close the window.\" && /usr/sbin/cygserver & 2> /dev/null"
bash --login -i