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
cd 信息收集一条龙
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

3. 安装可选依赖（用于PDF报告）
```bash
pip install weasyprint
```

## 使用方法

### 命令行使用

#### 基本扫描
```bash
# 扫描单个目标的所有模块
python main.py -t example.com

# 扫描多个模块
python main.py -t example.com -m subdomain,port,dns

# 指定线程数和超时时间
python main.py -t example.com --threads 50 --timeout 10
```

#### 高级扫描
```bash
# 从文件读取目标列表
python main.py -f targets.txt -m all -o report.html

# 使用自定义字典
python main.py -t example.com -m subdomain --wordlist my_subdomains.txt

# 扫描特定端口范围
python main.py -t example.com -m port --wordlist "1-1000"
```

#### 生成报告
```bash
# 生成HTML报告
python main.py -t example.com -m all -o report.html

# 生成PDF报告（需要安装weasyprint）
python main.py -t example.com -m all -o report.pdf

# 生成JSON报告
python main.py -t example.com -m all -o report.json
```

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

task = response.json()
task_id = task['task_id']

# 查询任务状态
while True:
    response = requests.get(f'http://localhost:8080/api/v1/scan/{task_id}')
    task = response.json()
    
    if task['status'] in ['completed', 'failed']:
        break
    
    print(f"Status: {task['status']}")
    time.sleep(2)

# 获取结果
print(json.dumps(task['result'], indent=2))
```

## 配置文件

工具使用`config.yaml`进行配置，主要配置项包括：

```yaml
scan:
  default_threads: 30      # 默认线程数
  default_timeout: 5       # 默认超时时间（秒）
  max_threads: 200         # 最大线程数

subdomain:
  brute_force: true        # 启用暴力破解
  search_engines: true     # 启用搜索引擎搜索
  dns_servers:             # DNS服务器列表
    - 8.8.8.8
    - 1.1.1.1

port:
  top_ports: [21,22,23,25,53,80,443,8080]  # 常用端口

vulnerability:
  test_xss: true           # 测试XSS漏洞
  test_sqli: true          # 测试SQL注入
  test_command_injection: false  # 测试命令注入

api:
  enabled: true
  host: "0.0.0.0"
  port: 8000
  cors_enabled: true       # 启用CORS
```

## 输出示例

### HTML报告

HTML报告包含：
- 执行摘要
- 目标概览
- 详细扫描结果
- 漏洞和警告信息
- 风险等级评估

### JSON输出

```json
{
  "metadata": {
    "generated_at": "2024-01-31T12:00:00",
    "tool_name": "网络安全信息收集工具",
    "version": "1.0.0"
  },
  "summary": {
    "total_targets": 1,
    "total_vulnerabilities": 3,
    "risk_level": "medium"
  },
  "targets": [
    {
      "target": "example.com",
      "risk_level": "medium",
      "results": {
        "subdomain": {
          "subdomains": ["www.example.com", "api.example.com"],
          "total_found": 2
        },
        "port": {
          "open_ports": [
            {"port": 80, "service": "HTTP", "state": "open"},
            {"port": 443, "service": "HTTPS", "state": "open"}
          ],
          "open_count": 2
        }
      }
    }
  ]
}
```

## 注意事项

### 法律声明

本工具仅供教育和授权测试使用。使用本工具扫描目标前，请确保您已获得适当的授权。未经授权的网络扫描可能违反法律法规。

### 性能考虑

- 大规模扫描时，建议使用较低的线程数以避免对目标造成过大压力
- 某些功能（如PDF生成）需要额外的系统依赖
- 网络扫描可能需要管理员权限

### 故障排除

1. **端口扫描失败**
   - 检查是否需要管理员权限
   - 确认防火墙设置

2. **SSL证书分析失败**
   - 检查目标是否支持HTTPS
   - 确认端口是否正确

3. **PDF报告生成失败**
   - 确认weasyprint已安装
   - 检查系统字体配置

## 贡献

欢迎提交Issue和Pull Request来改进这个工具。

## 许可证

本项目采用MIT许可证 - 详见LICENSE文件。

## 更新日志

### v1.0.0 (2024-01-31)
- 初始版本发布
- 实现所有核心功能模块
- 支持HTML/PDF/JSON报告生成
- 提供API接口
- 支持多线程扫描
