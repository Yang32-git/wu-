# GitHub 上传指南

## 📋 准备工作

### 1. 安装Git
如果还没有安装Git，请先下载安装：
- Windows: https://git-scm.com/download/win
- Mac: `brew install git`
- Linux: `sudo apt-get install git`

### 2. 创建GitHub账号
访问 https://github.com 注册账号（如果还没有）

### 3. 配置Git
打开命令行，配置你的Git信息：

```bash
git config --global user.name "你的名字"
git config --global user.email "你的邮箱@example.com"
```

## 🚀 上传步骤

### 方法1：使用Git命令行（推荐）

#### 步骤1：初始化Git仓库

```bash
cd "e:\信息收集一条龙"
git init
git add .
git commit -m "Initial commit: 网络安全信息收集工具"
```

#### 步骤2：在GitHub创建仓库

1. 登录 https://github.com
2. 点击右上角的 "+" → "New repository"
3. 填写仓库信息：
   - Repository name: `cyber-security-recon-tool`（或其他你喜欢的名字）
   - Description: `网络安全信息收集工具 - 支持子域名、端口、漏洞扫描等10个功能模块`
   - 选择 "Public"（公开）或 "Private"（私有）
   - 不要勾选 "Initialize this repository with a README"
4. 点击 "Create repository"

#### 步骤3：连接本地仓库到GitHub

在GitHub创建仓库后，会看到一个页面，选择 "HTTPS" 选项卡，复制类似这样的命令：

```bash
git remote add origin https://github.com/你的用户名/仓库名.git
```

#### 步骤4：推送代码到GitHub

```bash
git branch -M main
git push -u origin main
```

如果是第一次推送，会要求你输入GitHub的用户名和密码（或使用Token）

#### 步骤5：验证上传

访问 `https://github.com/你的用户名/仓库名` 查看是否上传成功

---

### 方法2：使用GitHub Desktop（图形界面）

#### 步骤1：下载并安装GitHub Desktop

https://desktop.github.com/

#### 步骤2：登录GitHub账号

打开GitHub Desktop，使用你的GitHub账号登录

#### 步骤3：添加本地仓库

1. 点击 "File" → "Add local repository"
2. 选择文件夹：`e:\信息收集一条龙`
3. 如果提示没有Git仓库，点击 "Create a repository"
4. 填写信息：
   - Name: `信息收集一条龙` 或 `cyber-security-recon-tool`
   - Description: 填写项目描述
   - 选择 "Git ignore" 模板: Python
   - 点击 "Create repository"

#### 步骤4：提交更改

1. 在左侧会看到所有文件
2. 填写提交信息: `Initial commit: 网络安全信息收集工具`
3. 点击 "Commit to main"

#### 步骤5：发布到GitHub

1. 点击 "Publish repository"
2. 勾选 "Keep this code private"（如果想设为私有）
3. 点击 "Publish repository"

---

### 方法3：使用VS Code（如果你使用VS Code）

#### 步骤1：打开项目

在VS Code中打开 `e:\信息收集一条龙` 文件夹

#### 步骤2：初始化Git

1. 点击左侧的源代码管理图标（或按 Ctrl+Shift+G）
2. 点击 "Initialize Repository"
3. 填写提交信息
4. 点击 "Commit"

#### 步骤3：发布到GitHub

1. 点击 "Publish to GitHub"
2. 选择 "Private" 或 "Public"
3. 点击 "Publish"

---

## 🔧 常见问题解决

### 问题1：推送时提示认证失败

**解决方案：**

1. 从2021年开始，GitHub不再支持密码认证，需要使用Personal Access Token
2. 生成Token：
   - 登录GitHub
   - Settings → Developer settings → Personal access tokens
   - 点击 "Generate new token"
   - 选择 "repo" 权限
   - 点击 "Generate token"
   - 复制生成的Token（注意：只显示一次）
3. 使用Token代替密码进行推送

### 问题2：文件太大无法上传

**解决方案：**

如果是data目录中的字典文件太大：

```bash
# 先从暂存区移除
git rm --cached data/subdomains.txt data/directory.txt

# 提交更改
git add .
git commit -m "Remove large dictionary files"

# 重新推送
git push origin main
```

然后可以考虑：
1. 使用Git LFS (Large File Storage)
2. 或者提供下载链接而不是直接提交到仓库

### 问题3：推送时提示 "src refspec main does not match"

**解决方案：**

```bash
git branch -M main
git push -u origin main
```

### 问题4：Windows路径问题

如果在Windows上遇到路径问题，使用双引号：

```bash
cd "e:\信息收集一条龙"
```

---

## 📦 后续更新

### 添加新功能后更新

```bash
# 添加所有更改的文件
git add .

# 提交更改
git commit -m "添加新功能：xxx"

# 推送到GitHub
git push origin main
```

### 查看状态

```bash
# 查看文件状态
git status

# 查看提交历史
git log

# 查看远程仓库信息
git remote -v
```

---

## 📝 建议的README.md优化

上传成功后，建议优化README.md文件：

1. 添加项目截图（GUI界面）
2. 添加功能演示GIF
3. 添加使用视频链接
4. 添加贡献者指南
5. 添加许可证信息

---

## 🎯 快速命令汇总

```bash
# 初始化
cd "e:\信息收集一条龙"
git init

# 添加文件
git add .

# 提交
git commit -m "Initial commit"

# 连接远程仓库
git remote add origin https://github.com/你的用户名/仓库名.git

# 推送
git branch -M main
git push -u origin main
```

---

## 🌟 下一步建议

1. **添加许可证**：在项目根目录添加LICENSE文件
2. **创建Issue模板**：方便用户反馈问题
3. **设置GitHub Pages**：可以展示在线演示
4. **添加CI/CD**：自动化测试和部署
5. **创建Wiki**：详细文档

---

## 📞 需要帮助？

如果遇到问题：
1. 查看GitHub官方文档：https://docs.github.com
2. 查看Git文档：https://git-scm.com/doc
3. 提交Issue到本仓库

祝你上传顺利！🎉
