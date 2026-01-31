@echo off
echo ========================================
echo GitHub 上传初始化工具
echo ========================================
echo.

cd "e:\信息收集一条龙"

echo 步骤1: 初始化Git仓库...
git init
if %errorlevel% neq 0 (
    echo [错误] Git未安装或未配置环境变量
    echo 请访问 https://git-scm.com/download/win 下载安装Git
    pause
    exit /b 1
)

echo.
echo 步骤2: 添加所有文件...
git add .

echo.
echo 步骤3: 创建初始提交...
git commit -m "Initial commit: 网络安全信息收集工具"

echo.
echo 步骤4: 检查Git配置...
git config user.name >nul 2>&1
if %errorlevel% neq 0 (
    echo [警告] Git用户未配置
    echo 请运行以下命令配置Git:
    echo   git config --global user.name "你的名字"
    echo   git config --global user.email "你的邮箱@example.com"
)

echo.
echo ========================================
echo 本地Git仓库初始化完成！
echo ========================================
echo.
echo 下一步：
echo 1. 登录 https://github.com
echo 2. 创建新仓库（不要初始化README）
echo 3. 复制仓库的HTTPS地址
echo 4. 运行以下命令：
echo.
echo    git remote add origin [你的仓库地址]
echo    git branch -M main
echo    git push -u origin main
echo.
echo 或直接查看上传到GitHub.md获取详细步骤
echo.
pause
