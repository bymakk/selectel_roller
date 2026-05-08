@echo off
chcp 65001 >nul
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

:: ── 1. Найти Python 3.10+ ────────────────────────────────────────────────────
set "PYTHON3="
for %%C in (python3.13 python3.12 python3.11 python3.10 python3 python py) do (
  if not defined PYTHON3 (
    where %%C >nul 2>&1
    if not errorlevel 1 (
      %%C -c "import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>&1
      if not errorlevel 1 (
        set "PYTHON3=%%C"
      )
    )
  )
)

:: ── 2. Если Python не найден — пытаемся установить ───────────────────────────
if not defined PYTHON3 (
  echo.
  echo Python 3.10+ не найден. Пробую установить через winget...
  echo.
  winget install --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements >nul 2>&1
  if errorlevel 1 (
    echo winget не сработал, пробую через Windows Store...
    start ms-windows-store://pdp/?ProductId=9NCVDN91XZQP
    echo.
    echo Если магазин не открылся — скачайте Python вручную:
    echo   https://www.python.org/downloads/
    echo.
    echo ВАЖНО: при установке поставьте галочку "Add Python to PATH"
    echo После установки закройте это окно и запустите run.bat снова.
    pause
    exit /b 1
  )
  :: Обновляем PATH в текущем сеансе после winget
  for /f "tokens=*" %%P in ('where python 2^>nul') do set "PYTHON3=python"
  if not defined PYTHON3 (
    echo.
    echo Python установлен, но не найден в PATH.
    echo Закройте это окно, откройте новый терминал и запустите run.bat снова.
    pause
    exit /b 1
  )
)

for /f "tokens=*" %%V in ('!PYTHON3! --version 2^>^&1') do echo Используем !PYTHON3!: %%V

:: ── 3. Создать .venv и установить зависимости ────────────────────────────────
set "PY=%CD%\.venv\Scripts\python.exe"
if not exist "%PY%" (
  echo Создаю виртуальное окружение .venv...
  !PYTHON3! -m venv .venv
  echo Устанавливаю зависимости (занимает ~30 секунд при первом запуске^)...
  call "%PY%" -m pip install -q --upgrade pip
  call "%PY%" -m pip install -q -r "%CD%\requirements.txt"
) else (
  call "%PY%" -m pip install -q -r "%CD%\requirements.txt"
)

:: ── 4. Запустить программу ───────────────────────────────────────────────────
"%PY%" "%CD%\main.py" %*
