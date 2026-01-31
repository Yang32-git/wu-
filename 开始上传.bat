@echo off
echo ========================================
echo GitHub上传 - 最终操作指引
echo ========================================
echo.

echo [步骤1/3] Git本地仓库状态：
echo ----------------------------------------
cd "e:\信息收集一条龙"
git log --oneline -3
echo.

echo [步骤2/3] 检查远程仓库：
echo ----------------------------------------
git remote -v
echo.

echo [步骤3/3] 上传选项：
echo ========================================
echo.
echo 请选择上传方式：
echo 1. 一键自动上传（推荐）
echo 2. 打开说明文档
echo 3. 手动输入命令
echo 4. 退出
echo.
set /p choice="请输入选项 (1-4): "

if "%choice%"=="1" goto auto_upload
if "%choice%"=="2" goto open_docs
if "%choice%"=="3" goto manual
if "%choice%"=="4" goto end
goto start

:auto_upload
echo.
echo 启动一键上传工具...
echo.
call "一键上传到GitHub.bat"
goto end

:open_docs
echo.
echo 打开说明文档...
start "" "上传准备完成.md"
echo 请查看文档后按任意键继续...
pause >nul
goto start

:manual
echo.
echo 手动上传命令：
echo ----------------------------------------
echo 1. 访问 https://github.com/new 创建仓库
echo 2. 复制HTTPS地址
echo 3. 运行以下命令：
echo.
echo    git remote add origin [你的仓库地址]
echo    git branch -M main
echo    git push -u origin main
echo.
echo 4. 按提示输入用户名和Token
echo.
pause
goto end

:end
echo.
echo ========================================
echo 感谢使用！
echo ========================================
echo.
echo 其他资源：
echo - 上传到GitHub.md （详细指南）
echo - GitHub上传快速指南.md （快速参考）
echo - 立即上传到GitHub.md （立即行动）
echo.
pause
