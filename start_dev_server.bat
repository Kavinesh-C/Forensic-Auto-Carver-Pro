@echo off
echo ===================================
echo  Starting Development Environment
echo ===================================

echo.
echo [1] Starting Apache HTTPD Server with fast_patch optimizations...
REM IMPORTANT: Replace the path below with the correct path to httpd.exe on your system.
start "Apache Server" "C:\Apache24\bin\httpd.exe"

echo [2] Starting Python File Watcher for auto-reload...
REM This script will watch for .py changes and "touch" the run.wsgi file.
start "File Watcher" python watcher.py

echo.
echo ✅ Both processes started in new windows.
echo Optimizations from fast_patch.py are applied automatically via run.wsgi.
echo To stop, simply close both new command prompt windows.
pause

