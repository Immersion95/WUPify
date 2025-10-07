@echo off
cd /d "%~dp0"
python WUPify.py --path . --recursive
pause