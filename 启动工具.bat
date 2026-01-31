@echo off
chcp 65001 >nul
echo ========================================
echo 网络安全信息收集工具
echo ========================================
echo.

:menu
echo 请选择操作：
echo 1. 扫描单个域名
echo 2. 扫描多个目标（从文件）
echo 3. 启动桌面版GUI
echo 4. 启动API服务器
echo 5. 运行测试
echo 6. 查看帮助
echo 7. 退出
echo.
set /p choice="请输入选项 (1-7): "

if "%choice%"=="1" goto single_scan
if "%choice%"=="2" goto file_scan
if "%choice%"=="3" goto tkinter_gui
if "%choice%"=="4" goto api_mode
if "%choice%"=="5" goto test
if "%choice%"=="6" goto help
if "%choice%"=="7" goto end
echo 无效选项，请重新选择
goto menu

:single_scan
echo.
set /p target="请输入目标域名或IP: "
set /p modules="请输入模块 (如: subdomain,port,dns 或 all): "
if "%modules%"=="" set modules=all
set /p threads="请输入线程数 (默认: 30): "
if "%threads%"=="" set threads=30
set /p output="请输入输出文件名 (如: report.html，直接回车不生成报告): "

echo.
echo 开始扫描 %target%...
if "%output%"=="" (
    python main.py -t %target% -m %modules% --threads %threads%
) else (
    python main.py -t %target% -m %modules% --threads %threads% -o %output%
)
pause
goto menu

:file_scan
echo.
set /p file="请输入目标文件路径: "
set /p modules="请输入模块 (如: subdomain,port,dns 或 all): "
if "%modules%"=="" set modules=all
set /p output="请输入输出文件名 (如: report.html): "

echo.
echo 开始扫描文件中的目标...
python main.py -f %file% -m %modules% -o %output%
pause
goto menu

:tkinter_gui
echo.
echo 正在启动桌面版GUI...
echo 请等待GUI窗口打开...
echo.
python tkinter_gui.py
pause
goto menu

:api_mode
echo.
set /p port="请输入API服务器端口 (默认: 8000): "
if "%port%"=="" set port=8000
echo.
echo 启动API服务器...
echo 访问地址: http://localhost:%port%
echo API文档: http://localhost:%port%/
echo 按 Ctrl+C 停止服务器
echo.
python main.py --api --port %port%
pause
goto menu

:test
echo.
echo 运行功能测试...
python test_scan.py
pause
goto menu

:help
echo.
echo 使用说明：
echo 1. 扫描单个域名 - 输入目标域名或IP，选择要扫描的模块
echo 2. 扫描多个目标 - 从文件读取目标列表（每行一个）
echo 3. 桌面版GUI - 启动图形界面（推荐）
echo 4. API服务器 - 启动RESTful API服务器
echo 5. 运行测试 - 测试工具功能是否正常
echo 6. 查看帮助 - 显示此帮助信息
echo 7. 退出 - 退出程序
echo.
echo 可用模块：
echo - subdomain: 子域名扫描
echo - port: 端口探测
echo - service: 服务识别
echo - dns: DNS记录获取
echo - whois: WHOIS查询
echo - dir: 目录扫描
echo - vuln: 漏洞检测
echo - ssl: SSL证书分析
echo - network: 网络拓扑探测
echo - all: 所有模块
echo.
echo 示例：
echo - 快速扫描: python main.py -t example.com
echo - 完整扫描: python main.py -t example.com -m all -o report.html
echo - 端口扫描: python main.py -t example.com -m port --threads 50
echo.
pause
goto menu

:end
echo.
echo 感谢使用！
echo.
