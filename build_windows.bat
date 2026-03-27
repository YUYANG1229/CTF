@echo off
REM CTF Web Toolkit - Windows 构建脚本
REM 生成 dist\ctf-toolkit.exe（单文件可执行）
REM
REM 运行要求：
REM   - Windows 10/11
REM   - Python 3.9+ (https://www.python.org/downloads/)
REM   - 已添加 Python 到 PATH

echo === CTF Web Toolkit Windows 构建 ===

cd /d "%~dp0"

REM ── 1. 检查 Python ───────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [-] 未找到 Python，请安装 Python 3.9+
    echo     下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo [*] Python 版本:
python --version

REM ── 2. 创建/激活虚拟环境 ─────────────────────
if not exist ".venv\" (
    echo [*] 创建虚拟环境...
    python -m venv .venv
)

call .venv\Scripts\activate.bat

REM ── 3. 安装依赖 ──────────────────────────────
echo [*] 安装依赖...
pip install -q -r requirements.txt
pip install -q pyinstaller pyinstaller-hooks-contrib

REM ── 4. 清理旧构建 ─────────────────────────────
if exist "dist\ctf-toolkit.exe" del /f "dist\ctf-toolkit.exe"
echo [*] 清理旧构建完成

REM ── 5. 构建 ──────────────────────────────────
echo [*] 构建 Windows 可执行文件...
python -m PyInstaller ctf_toolkit.spec --clean --noconfirm

REM ── 6. 验证 ──────────────────────────────────
if exist "dist\ctf-toolkit.exe" (
    echo.
    echo [+] 构建成功: dist\ctf-toolkit.exe
    echo [+] 大小:
    for %%A in ("dist\ctf-toolkit.exe") do echo     %%~zA bytes
    echo.
    echo === 测试运行 ===
    dist\ctf-toolkit.exe --help
    echo.
    echo 使用方法：
    echo   dist\ctf-toolkit.exe scan http://target.com
    echo   dist\ctf-toolkit.exe sqli http://target.com --param id
    echo   dist\ctf-toolkit.exe xxe http://target.com --action detect
) else (
    echo [-] 构建失败！检查上方错误信息
    pause
    exit /b 1
)

REM ── 7. 可选：打包为 .zip ─────────────────────
if "%1"=="package" (
    for /f "tokens=2 delims= " %%I in ('date /t') do set TODAY=%%I
    set TODAY=%TODAY:/=%
    set ZIPFILE=dist\ctf-toolkit-windows-x64-%TODAY%.zip
    powershell -command "Compress-Archive -Path 'dist\ctf-toolkit.exe' -DestinationPath '%ZIPFILE%' -Force"
    echo [+] 打包完成: %ZIPFILE%
)

pause
