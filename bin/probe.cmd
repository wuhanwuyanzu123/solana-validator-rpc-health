@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "PYTHON_EXE="
where python >nul 2>nul
if not errorlevel 1 (
  python --version >nul 2>nul
  if not errorlevel 1 set "PYTHON_EXE=python"
)
if not defined PYTHON_EXE (
  set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
)
if /I not "%PYTHON_EXE%"=="python" if not exist "%PYTHON_EXE%" (
  echo Python was not found. Install Python or put python.exe on PATH. 1>&2
  exit /b 1
)
"%PYTHON_EXE%" "%SCRIPT_DIR%solana-validator-rpc-health.py" %*
exit /b %ERRORLEVEL%
