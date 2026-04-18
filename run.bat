@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "PY=%CD%\.venv\Scripts\python.exe"
if not exist "%PY%" (
  where python >nul 2>&1
  if errorlevel 1 (
    echo python not found in PATH >&2
    exit /b 1
  )
  python -m venv .venv
  call "%PY%" -m pip install -q --upgrade pip
  call "%PY%" -m pip install -q -r "%CD%\requirements.txt"
)
"%PY%" "%CD%\main.py" %*
