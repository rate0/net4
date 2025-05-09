@echo off
SETLOCAL
REM ======================================================
REM  Net4 launcher script for Windows
REM  (auto-creates venv, installs deps, запускает Net4)
REM ======================================================

REM Полный путь к директории, где лежит скрипт
SET "SCRIPT_DIR=%~dp0"
PUSHD "%SCRIPT_DIR%"

REM ---------- 1. Создание виртуального окружения ----------
IF NOT EXIST "venv" (
    ECHO [Net4] First-time setup: creating virtual environment...
    python -m venv "venv" || GOTO :error

    ECHO [Net4] Installing Python dependencies...
    "venv\Scripts\pip.exe" install -r "requirements.txt" || GOTO :error
)

REM ---------- 2. Настройка Scapy HTTP/HTTPS (один раз) ----------
IF NOT EXIST "venv\.scapy_http_installed" (
    ECHO [Net4] Setting up HTTP/HTTPS packet support...
    "venv\Scripts\python.exe" "setup_scapy_http.py" || GOTO :error
    TYPE NUL > "venv\.scapy_http_installed"
)

REM ---------- 3. Запуск приложения ----------
ECHO [Net4] Launching application...
"venv\Scripts\python.exe" "main.py"

GOTO :eof

:error
ECHO.
ECHO [Net4] *** Setup failed. See error messages above. ***
PAUSE
POPD
ENDLOCAL
EXIT /B 1
