@echo off
setlocal enabledelayedexpansion

:: === Настройки ===
set REMOTE_USER=daniil10295
set REMOTE_HOST=10.0.0.50
set REMOTE_PATH=/home/%REMOTE_USER%/deploy/dosp_server
set FILE_LIST=files.txt
set PYTHON_SCRIPT=server.py

:: === Копирование файлов ===
for /f "usebackq delims=" %%f in ("%FILE_LIST%") do (
    echo Копирование: %%f
    scp -r "%%f" %REMOTE_USER%@%REMOTE_HOST%:%REMOTE_PATH%
)

:: === Перезапуск скрипта на сервере ===
ssh %REMOTE_USER%@%REMOTE_HOST% ^
"cd %REMOTE_PATH% && ^
if [ -f .server.pid ]; then \
  kill \$(cat .server.pid) 2>/dev/null || true; \
  rm -f .server.pid; \
fi && \
nohup python3 %PYTHON_SCRIPT% > server.log 2>&1 & echo \$! > .server.pid"