@echo off
cd /d "%~dp0.."
python -m uvicorn adapter.app:app --host 0.0.0.0 --port 8080
pause
