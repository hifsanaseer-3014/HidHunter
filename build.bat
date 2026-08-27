@echo off
echo ============================================
echo   HIDHunter - Building standalone .exe
echo ============================================
echo.

echo [1/3] Installing PyInstaller...
pip install pyinstaller --quiet

echo [2/3] Cleaning old build folders...
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
del HIDHunter.spec 2>nul

echo [3/3] Building HIDHunter.exe (this may take a minute)...
pyinstaller --onefile --noconsole --name HIDHunter hidhunter.py

echo.
if exist "dist\HIDHunter.exe" (
    echo ============================================
    echo   SUCCESS! Your .exe is ready at:
    echo   dist\HIDHunter.exe
    echo ============================================
) else (
    echo ============================================
    echo   Something went wrong - check the messages above.
    echo ============================================
)
pause
