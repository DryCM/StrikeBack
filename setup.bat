@echo off
echo ============================================
echo   StrikeBack - Instalacion de dependencias
echo ============================================

if not exist ".venv" (
    uv venv .venv --python 3.14
)

.venv\Scripts\pip.exe install -r requirements.txt

if %ERRORLEVEL% == 0 (
    echo.
    echo [OK] Dependencias instaladas correctamente.
    echo.
    echo IMPORTANTE: Edita config.py y agrega tu API key antes de ejecutar.
    echo.
    echo Para ejecutar StrikeBack:
    echo   .venv\Scripts\python.exe main.py
    echo.
) else (
    echo [ERROR] Fallo la instalacion. Asegurate de tener uv instalado.
)
pause
