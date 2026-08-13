@echo off
chcp 65001 > nul
cd /d "%~dp0"
set "PYTHON_COMMAND="
where python > nul 2> nul && set "PYTHON_COMMAND=python"
if not defined PYTHON_COMMAND where py > nul 2> nul && set "PYTHON_COMMAND=py -3"
if not defined PYTHON_COMMAND (
  echo Python 3을 찾지 못했습니다.
  echo https://www.python.org/downloads/ 에서 Python을 설치할 때
  echo Add Python to PATH 항목을 선택한 후 다시 실행하세요.
  pause
  exit /b 1
)
if not exist results mkdir results
%PYTHON_COMMAND% scripts\run_empirical_validation.py --output results
if errorlevel 1 (
  echo.
  echo 검증 항목 중 실패가 있습니다. results 폴더의 보고서를 확인하세요.
) else (
  echo.
  echo 모든 합성 데이터 검증 항목을 통과했습니다.
)
pause
