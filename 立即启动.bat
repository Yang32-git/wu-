@echo off
echo =======================================================================
echo 网络安全信息收集工具 - Tkinter桌面版
echo =======================================================================
echo.

echo 正在启动桌面版GUI...
echo.
echo 注意: 这个版本不依赖Flask，不依赖浏览器
echo 使用Python内置的tkinter库，100%兼容
echo.

REM 直接启动tkinter GUI
python tkinter_gui.py

echo.
echo =======================================================================
echo GUI已关闭
echo =======================================================================
echo.
if %errorlevel% neq 0 (
    echo 启动失败，请查看上面的错误信息
    echo.
    echo 如果仍然无法启动，建议:
    echo 1. 重新安装Python 3.8-3.10
    echo 2. 安装时勾选"tcl/tk"选项
    echo 3. 使用命令行模式: python main.py -t example.com -m dns,whois
    echo.
)

pause
