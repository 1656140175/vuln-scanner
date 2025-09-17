@echo off
REM VulnMiner 系统启动器 - Windows批处理文件
REM 高级全自动化漏洞扫描与赏金获取系统
REM 
REM 支持两种模式:
REM - SCAN 模式: 手动目标输入，可选择自动报告提交  
REM - AUTO 模式: 从漏洞赏金平台自动获取目标并自动提交报告
REM
REM 使用方法:
REM   start.bat                          - 显示使用示例
REM   start.bat scan --target URL        - 手动目标扫描
REM   start.bat auto --platform NAME     - 自动化漏洞赏金扫描
REM   start.bat --health-check           - 系统健康检查
REM   start.bat --install-tools          - 安装必需工具

setlocal enabledelayedexpansion

REM 检查是否安装Python 3.8+
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ 未安装Python或Python不在PATH中
    echo 请从 https://python.org 安装Python 3.8或更高版本
    pause
    exit /b 1
)

REM 检查Python版本
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set MAJOR=%%a
    set MINOR=%%b
)

if %MAJOR% LSS 3 (
    echo ❌ Python %PYTHON_VERSION% 版本过低。需要Python 3.8或更高版本
    pause
    exit /b 1
)

if %MAJOR% EQU 3 if %MINOR% LSS 8 (
    echo ❌ Python %PYTHON_VERSION% 版本过低。需要Python 3.8或更高版本  
    pause
    exit /b 1
)

REM 显示横幅
echo.
echo ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███╗   ███╗██╗███╗   ██╗███████╗██████╗ 
echo ██║   ██║██║   ██║██║     ████╗  ██║    ████╗ ████║██║████╗  ██║██╔════╝██╔══██╗
echo ██║   ██║██║   ██║██║     ██╔██╗ ██║    ██╔████╔██║██║██╔██╗ ██║█████╗  ██████╔╝
echo ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ██║╚██╔╝██║██║██║╚██╗██║██╔══╝  ██╔══██╗
echo  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ██║ ╚═╝ ██║██║██║ ╚████║███████╗██║  ██║
echo   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
echo.
echo     高级全自动化漏洞扫描与赏金获取系统
echo     版本: 1.0.0 ^| 模式: 个人使用 ^| 平台: Windows
echo.
echo     🔍 SCAN 模式: 手动目标输入智能扫描
echo     🤖 AUTO 模式: 漏洞赏金平台自动目标获取
echo     📊 实时进度跟踪和ML时间估算  
echo     📋 多格式报告 (PDF, HTML, JSON, SARIF)
echo     🚀 跨平台支持 (Windows, Linux, Google Colab)
echo.

REM 更改到脚本目录
cd /d "%~dp0"

REM 检查是否没有提供参数
if "%1"=="" (
    echo 🚀 快速开始示例:
    echo.
    echo 1. SCAN 模式 - 手动目标扫描:
    echo    start.bat scan --target https://example.com --pipeline quick
    echo    start.bat scan --target https://example.com --pipeline comprehensive --submit
    echo.
    echo 2. AUTO 模式 - 自动化漏洞赏金扫描:
    echo    start.bat auto --platform hackerone --max-targets 5
    echo    start.bat auto --platform bugcrowd --continuous
    echo.
    echo 3. 系统管理:
    echo    start.bat --validate-config
    echo    start.bat --health-check
    echo    start.bat --install-tools
    echo.
    echo 4. 高级扫描:
    echo    start.bat scan --target-list targets.txt --pipeline webapp --format pdf,html
    echo    start.bat scan --target 192.168.1.0/24 --pipeline network --aggressive
    echo.
    echo 📖 详细帮助: start.bat --help
    echo 📖 模式专用帮助: start.bat scan --help ^| start.bat auto --help
    echo.
    pause
    exit /b 0
)

REM 使用所有参数运行Python启动器
python start.py %*

REM 检查退出代码，如有错误则暂停
if errorlevel 1 (
    echo.
    echo ❌ VulnMiner 退出时发生错误，错误代码 %errorlevel%
    echo 按任意键退出...
    pause >nul
)