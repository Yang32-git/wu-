# 网络安全信息收集工具

一个全面的网络安全信息收集工具，支持子域名扫描、端口探测、服务识别、漏洞检测、WHOIS查询、DNS记录获取、网站目录扫描、敏感信息检测、SSL证书分析、网络拓扑探测等功能。

## 功能特性

- **多模块扫描**
  - 子域名扫描：支持暴力破解、搜索引擎、证书透明度等多种方式
  - 端口探测：支持SYN、TCP扫描，识别开放端口
  - 服务识别：识别开放端口上的服务类型和版本
  - WHOIS查询：获取域名注册信息
  - DNS记录：获取各种DNS记录类型
  - 目录扫描：扫描网站目录和敏感文件
  - 漏洞检测：检测XSS、SQL注入、命令注入等常见漏洞
  - SSL分析：分析SSL证书安全性和配置
  - 网络拓扑：路由追踪和网络发现

- **高性能**
  - 多线程并发扫描
  - 可配置的线程数和超时时间
  - 智能任务调度

- **API支持**
  - 提供RESTful API接口
  - 支持异步任务处理
  - 实时任务状态查询

- **报告生成**
  - 生成详细的HTML报告
  - 支持PDF报告导出
  - 结构化的JSON输出
  - 风险等级评估

- **跨平台**
  - 支持Windows、Linux、macOS
  - 基于Python开发，易于部署

## 安装

### 系统要求

- Python 3.6+
- 操作系统：Windows 7+/Linux/macOS

### 安装步骤

1. 克隆或下载项目
```bash
git clone <repository-url>
```

2. 安装依赖
```bash
cd 信息收集一条龙
pip install -r requirements.txt
```

3. 运行工具
```bash
# 命令行模式
python main.py -t example.com -m all

# GUI模式
python tkinter_gui.py
```

## 使用说明

### 命令行模式

#### 基本用法

```bash
# 扫描单个目标
python main.py -t example.com -m all

# 指定模块扫描
python main.py -t example.com -m subdomain,port,dns

# 批量扫描
python main.py -f targets.txt -m all -o report.html

# 生成JSON报告
python main.py -t example.com -m all -o report.json
```

#### 参数说明

- `-t, --target`: 目标域名或IP地址
- `-f, --file`: 从文件读取目标列表
- `-m, --modules`: 启用的模块（subdomain,port,service,dns,whois,dir,vuln,ssl,network,all）
- `--threads`: 线程数（默认：30）
- `--timeout`: 超时时间（默认：5秒）
- `-o, --output`: 输出报告文件
- `-v, --verbose`: 详细输出
- `--api`: 启动API服务器模式
- `--api-port`: API服务器端口（默认：8000）

### 模块说明

- `subdomain`: 子域名扫描
- `port`: 端口探测
- `service`: 服务识别
- `dns`: DNS记录获取
- `whois`: WHOIS查询
- `dir`: 目录扫描
- `vuln`: 漏洞检测
- `ssl`: SSL证书分析
- `network`: 网络拓扑探测
- `all`: 所有模块

### 桌面版GUI模式

#### 启动Tkinter GUI（推荐）
```bash
# 启动桌面版GUI
python tkinter_gui.py

# 或者使用快速启动脚本
python 立即启动.bat
```

GUI功能特点：
- 🎨 原生桌面应用程序
- 📊 图形化界面操作
- ✅ 模块勾选选择
- 📈 实时结果显示
- 💾 报告一键生成
- 🖥️ 跨平台支持（Windows/Linux/macOS）

#### GUI使用步骤

1. **启动GUI**
   ```bash
   python tkinter_gui.py
   ```

2. **输入目标**
   - 在"目标列表"中输入域名或IP（每行一个）
   - 示例：
     ```
     example.com
     192.168.1.1
     test.example.com
     ```

3. **选择模块**
   - 勾选需要的扫描模块
   - 点击"全选"选择所有模块
   - 使用预设快速配置：
     - 信息收集预设：subdomain + dns + whois
     - 安全评估预设：port + service + vuln + ssl
     - 网络探测预设：port + service + network

4. **设置参数**
   - 线程数：默认30
   - 超时时间：默认5秒

5. **开始扫描**
   - 点击"开始扫描"按钮
   - 查看实时进度和结果

6. **生成报告**
   - 扫描完成后点击"生成报告"
   - 选择保存位置
   - 自动生成HTML报告

### API模式

#### 启动API服务器
```bash
python main.py --api --port 8080
```

#### API端点

- `POST /api/v1/scan` - 创建扫描任务
- `GET /api/v1/scan/{task_id}` - 获取任务状态/结果
- `GET /api/v1/scan` - 获取所有任务
- `GET /api/v1/info` - 获取扫描器信息
- `GET /api/v1/health` - 健康检查

#### API使用示例

```python
import requests
import time

# 创建扫描任务
response = requests.post('http://localhost:8080/api/v1/scan', json={
    'target': 'example.com',
    'modules': ['subdomain', 'port', 'vuln'],
    'threads': 30,
    'timeout': 5
})

task_id = response.json()['task_id']
print(f"任务已创建: {task_id}")

# 查询任务状态
while True:
    result = requests.get(f'http://localhost:8080/api/v1/scan/{task_id}').json()
    if result['status'] == 'completed':
        print("扫描完成！")
        print(result['results'])
        break
    elif result['status'] == 'failed':
        print("扫描失败！")
        break
    else:
        print(f"进度: {result['progress']}%")
        time.sleep(2)
```

### GUI vs 命令行对比

| 特性 | GUI模式 | 命令行模式 |
|------|---------|------------|
| 易用性 | ⭐⭐⭐⭐⭐ 图形操作 | ⭐⭐⭐ 需要记忆命令 |
| 实时性 | ⭐⭐⭐⭐⭐ 实时显示 | ⭐⭐⭐ 定期刷新 |
| 交互性 | ⭐⭐⭐⭐⭐ 交互式 | ⭐⭐ 批处理 |
| 可视化 | ⭐⭐⭐⭐⭐ 图表展示 | ⭐⭐ 文本输出 |
| 跨平台 | ⭐⭐⭐⭐⭐ 原生应用 | ⭐⭐⭐⭐ Python脚本 |
| 批量操作 | ⭐⭐⭐⭐ 列表输入 | ⭐⭐⭐⭐ 文件输入 |
| 报告生成 | ⭐⭐⭐⭐ 一键生成 | ⭐⭐⭐ 命令生成 |

## 配置说明

### 配置文件

编辑 `config.yaml` 文件来自定义工具行为：

```yaml
# 扫描配置
scanning:
  threads: 30                    # 默认线程数
  timeout: 5                     # 默认超时时间（秒）
  wordlist_dir: "data"          # 字典文件目录
  
# 模块配置
modules:
  subdomain:
    enabled: true
    wordlist: "subdomains.txt"   # 子域名字典
    use_search_engines: true     # 使用搜索引擎
    use_cert_transparency: true  # 使用证书透明度
    
  port:
    enabled: true
    ports: "1-1000"              # 扫描端口范围
    top_ports: 1000              # 常用端口数
    
  # 更多配置...
```

### 自定义字典

- 子域名字典：`data/subdomains.txt`
- 目录字典：`data/directory.txt`

## 示例

### 示例1：基础信息收集

```bash
python main.py -t example.com -m subdomain,dns,whois -o basic_info.html
```

### 示例2：安全评估

```bash
python main.py -t example.com -m port,service,vuln,ssl -o security_assessment.html
```

### 示例3：网络探测

```bash
python main.py -t 192.168.1.0/24 -m port,service,network -o network_discovery.html
```

### 示例4：批量扫描

```bash
# targets.txt 内容：
# example1.com
# example2.com
# 192.168.1.1

python main.py -f targets.txt -m all -o batch_report.html
```

## 注意事项

### 法律声明

本工具仅用于合法的安全测试和教育目的。使用本工具扫描目标前，请确保你已获得适当的授权。未经授权的扫描可能违反法律法规。

### 性能建议

1. **线程数设置**：
   - 内网扫描：可设置较高（100-200）
   - 公网扫描：建议较低（10-30）
   - 默认：30

2. **超时时间**：
   - 稳定网络：5秒
   - 不稳定网络：10-15秒

3. **扫描策略**：
   - 大范围扫描：先使用 `-m port` 快速探测
   - 针对性扫描：使用特定模块组合
   - 全面评估：使用 `-m all`

### 常见问题

#### 1. 导入错误
```
ImportError: No module named 'xxx'
```
解决方案：
```bash
pip install -r requirements.txt
```

#### 2. 权限问题
```
PermissionError: [Errno 13] Permission denied
```
解决方案：
- 以管理员身份运行
- 检查文件和目录权限

#### 3. 扫描超时
```
TimeoutError: [WinError 10060]
```
解决方案：
- 增加超时时间：`--timeout 10`
- 检查网络连接
- 减少线程数

## 更新日志

### v1.0.0 (2024-01-31)
- 初始版本发布
- 支持10个功能模块
- 支持命令行和GUI模式
- 支持报告生成功能

## 贡献

欢迎提交Issue和Pull Request！

## 许可证

MIT License

## 联系方式

- 项目地址: https://github.com/Yang32-git/wu-
- 问题反馈: https://github.com/Yang32-git/wu-/issues

## 致谢

感谢所有开源社区的支持和贡献！
