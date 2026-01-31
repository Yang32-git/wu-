@echo off
echo ========================================
echo 一键上传到GitHub工具
echo ========================================
echo.

cd "e:\信息收集一条龙"

echo 步骤1: 检查Git状态...
git status >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] Git仓库未初始化
    echo 请运行: 初始化Git仓库.bat
    pause
    exit /b 1
)

echo [成功] Git仓库已初始化
echo.

echo 步骤2: 检查远程仓库...
git remote -v | findstr "origin" >nul 2>&1
if %errorlevel% equ 0 (
    echo [成功] 已配置远程仓库
    echo.
    echo 步骤3: 推送代码到GitHub...
    git push -u origin main
    if %errorlevel% equ 0 (
        echo.
        echo ========================================
        echo 上传成功！
        echo ========================================
        git remote -v
    ) else (
        echo [错误] 推送失败
        echo 请检查网络连接和GitHub权限
    )
    pause
    exit /b 0
)

echo [信息] 尚未配置远程仓库
echo.
echo ========================================
echo 请按以下步骤操作：
echo ========================================
echo.
echo 1. 访问 https://github.com/new
echo 2. 创建新仓库：
echo    - Repository name: cyber-security-recon-tool
echo    - Description: 网络安全信息收集工具
echo    - 选择 Public 或 Private
echo    - 不要勾选 "Initialize with README"
echo 3. 创建完成后，复制HTTPS地址
echo    （格式: https://github.com/你的用户名/仓库名.git）
echo.
echo 4. 回到此窗口，输入仓库地址：
echo.
set /p repo_url="请输入GitHub仓库地址: "

if "%repo_url%"=="" (
    echo [错误] 未输入仓库地址
    pause
    exit /b 1
)

echo.
echo 步骤3: 配置远程仓库...
git remote add origin %repo_url%

if %errorlevel% neq 0 (
    echo [错误] 配置远程仓库失败
    pause
    exit /b 1
)

echo [成功] 远程仓库已配置
echo.

echo 步骤4: 推送代码到GitHub...
git branch -M main
git push -u origin main

if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo 上传成功！
    echo ========================================
    echo.
    echo 访问 %repo_url% 查看你的代码
) else (
    echo.
    echo [错误] 推送失败
    echo 可能的原因：
    echo 1. GitHub账号未登录
    echo 2. 没有推送权限
    echo 3. 网络连接问题
    echo.
    echo 解决方案：
    echo 1. 检查GitHub用户名和密码/Token
    echo 2. 检查仓库地址是否正确
    echo 3. 检查网络连接
)

pause
