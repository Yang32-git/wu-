# GitHub上传快速指南

## 🎯 一键上传脚本（推荐Windows用户）

双击运行：
```
初始化Git仓库.bat
```

这个脚本会自动：
1. ✅ 初始化Git仓库
2. ✅ 添加所有文件
3. ✅ 创建初始提交
4. ✅ 检查Git配置
5. ✅ 提供下一步操作指引

---

## 📋 完整上传步骤

### 步骤1：初始化Git仓库

```bash
cd "e:\信息收集一条龙"
git init
git add .
git commit -m "Initial commit: 网络安全信息收集工具"
```

### 步骤2：在GitHub创建仓库

1. 访问 https://github.com/new
2. 填写仓库信息：
   - Repository name: `cyber-security-recon-tool`
   - Description: 全面的网络安全信息收集工具，支持10个功能模块
   - 选择 Public 或 Private
   - 不要勾选 "Initialize this repository with a README"
3. 点击 "Create repository"

### 步骤3：连接并推送

在GitHub创建仓库后，复制类似这样的命令（选择HTTPS）：

```bash
git remote add origin https://github.com/你的用户名/cyber-security-recon-tool.git
git branch -M main
git push -u origin main
```

### 步骤4：验证

访问 `https://github.com/你的用户名/cyber-security-recon-tool` 查看上传结果

---

## 📖 详细文档

查看完整的上传指南：
- **上传到GitHub.md** - 详细步骤和故障排除
- **清理完成.md** - 项目结构说明

---

## 🚀 项目特点

这个工具包含：
- ✅ 10个功能模块（子域名、端口、漏洞检测等）
- ✅ Tkinter桌面GUI
- ✅ API服务器模式
- ✅ 多线程支持
- ✅ 报告生成功能
- ✅ 跨平台支持

---

## 📝 下一步建议

上传成功后，可以：
1. 添加项目截图到README.md
2. 创建GitHub Pages展示文档
3. 设置Issues模板
4. 添加开源许可证
5. 编写贡献指南

---

**祝你上传成功！🎉**
