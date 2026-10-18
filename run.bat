@echo off
chcp 65001 >nul
REM Flow - Windows launcher
cd /d "%~dp0"
if not exist .venv (
  echo First-time setup...
  py -3 -m venv .venv || python -m venv .venv
  .venv\Scripts\pip install -q -r requirements.txt
)
start "" http://127.0.0.1:5000
.venv\Scripts\python app.py %*
pause
