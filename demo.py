#!/usr/bin/env python3
"""
网络安全信息收集工具 - 快速演示
演示工具的核心功能
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

def demo_modules():
    """演示各个扫描模块"""
    print("=" * 70)
    print("网络安全信息收集工具 - 功能演示")
    print("=" * 70)
    print()
    
    # 演示1: 子域名扫描器
    print("【1. 子域名扫描器】")
    print("- 支持DNS区域传输")
    print("- 搜索引擎发现 (crt.sh, CertSpotter等)")
    print("- 字典暴力破解")
    print("- 多线程并发扫描")
    print("- 自动验证子域名有效性")
    print()
    
    # 演示2: 端口扫描器
    print("【2. 端口扫描器】")
    print("- TCP端口扫描")
    print("- SYN扫描 (需要管理员权限)")
    print("- Banner抓取")
    print("- 服务版本识别")
    print("- 常用端口和自定义端口范围")
    print()
    
    # 演示3: 服务识别
    print("【3. 服务识别器】")
    print("- 基于Banner的服务识别")
    print("- 版本信息提取")
    print("- CPE (通用平台枚举) 生成")
    print("- 操作系统指纹识别")
    print("- 支持20+种常见服务")
    print()
    
    # 演示4: DNS记录扫描
    print("【4. DNS记录扫描器】")
    print("- 支持A, AAAA, MX, NS, TXT, CNAME, SOA, PTR记录")
    print("- 自定义DNS服务器")
    print("- DNS区域传输尝试")
    print("- 详细的记录信息解析")
    print()
    
    # 演示5: WHOIS查询
    print("【5. WHOIS查询器】")
    print("- 域名注册信息查询")
    print("- 注册商信息")
    print("- 创建/过期日期")
    print("- 名称服务器列表")
    print("- 状态信息")
    print()
    
    # 演示6: 目录扫描
    print("【6. 目录扫描器】")
    print("- 网站目录枚举")
    print("- 文件发现")
    print("- 状态码分析")
    print("- 目录列表检测")
    print("- 支持多种文件扩展名")
    print()
    
    # 演示7: 漏洞检测
    print("【7. 漏洞检测器】")
    print("- XSS漏洞检测")
    print("- SQL注入检测")
    print("- 命令注入检测")
    print("- 安全头检查 (CSP, HSTS等)")
    print("- SSL/TLS配置检查")
    print("- 信息泄露检测")
    print("- 风险等级评估")
    print()
    
    # 演示8: SSL证书分析
    print("【8. SSL证书分析器】")
    print("- 证书有效性检查")
    print("- 过期时间监控")
    print("- 证书链验证")
    print("- 加密套件分析")
    print("- 协议版本检测 (SSL 2.0/3.0, TLS 1.0/1.1/1.2/1.3)")
    print("- 自签名证书检测")
    print()
    
    # 演示9: 网络拓扑
    print("【9. 网络拓扑扫描器】")
    print("- 路由追踪 (traceroute)")
    print("- 网络信息收集")
    print("- TTL操作系统指纹")
    print("- 跳数分析")
    print()
    
    # 演示10: 核心引擎
    print("【10. 核心扫描引擎】")
    print("- 多模块协调调度")
    print("- 智能任务管理")
    print("- 线程池并发控制")
    print("- 统一的扫描接口")
    print("- 结果聚合和格式化")
    print()

def demo_usage():
    """演示使用方法"""
    print("=" * 70)
    print("使用示例")
    print("=" * 70)
    print()
    
    examples = [
        {
            "desc": "扫描单个域名（所有模块）",
            "cmd": "python main.py -t example.com -m all"
        },
        {
            "desc": "扫描特定模块",
            "cmd": "python main.py -t example.com -m subdomain,port,dns"
        },
        {
            "desc": "生成HTML报告",
            "cmd": "python main.py -t example.com -m all -o report.html"
        },
        {
            "desc": "批量扫描",
            "cmd": "python main.py -f targets.txt -m all -o batch_report.html"
        },
        {
            "desc": "启动API服务器",
            "cmd": "python main.py --api --port 8080"
        },
        {
            "desc": "使用自定义字典",
            "cmd": "python main.py -t example.com -m subdomain --wordlist my_subdomains.txt"
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"{i}. {example['desc']}")
        print(f"   {example['cmd']}")
        print()

def demo_structure():
    """演示项目结构"""
    print("=" * 70)
    print("项目结构")
    print("=" * 70)
    print()
    
    structure = """
信息收集一条龙/
├── main.py                           # 主程序入口
├── install.py                        # 安装脚本
├── requirements.txt                  # Python依赖
├── config.yaml                       # 配置文件
├── README.md                         # 详细文档
├── modules/                          # 核心模块
│   ├── core/                        # 核心引擎
│   │   └── recon_engine.py          # 扫描引擎
│   ├── scanning/                    # 扫描模块
│   │   ├── subdomain_scanner.py     # 子域名扫描
│   │   ├── port_scanner.py          # 端口扫描
│   │   ├── service_scanner.py       # 服务识别
│   │   ├── dns_scanner.py           # DNS和WHOIS
│   │   ├── directory_scanner.py     # 目录扫描
│   │   ├── vulnerability_scanner.py # 漏洞检测
│   │   └── ssl_scanner.py           # SSL和网络拓扑
│   ├── api/                         # API模块
│   │   └── api_server.py            # API服务器
│   ├── report/                      # 报告模块
│   │   └── report_generator.py      # 报告生成器
│   └── utils/                       # 工具模块
│       ├── logger.py                # 日志记录
│       └── config.py                # 配置管理
└── data/                            # 数据文件
    ├── subdomains.txt               # 子域名字典
    └── directory.txt                # 目录字典
"""
    print(structure)

def main():
    """主函数"""
    try:
        demo_modules()
        demo_usage()
        demo_structure()
        
        print("=" * 70)
        print("工具特点")
        print("=" * 70)
        print()
        print("* 10个功能模块，覆盖全面的信息收集需求")
        print("* 多线程并发，高效快速")
        print("* RESTful API接口，支持异步任务")
        print("* HTML/PDF/JSON多种报告格式")
        print("* 跨平台支持 (Windows/Linux/macOS)")
        print("* 详细的日志记录和错误处理")
        print("* 灵活的配置系统")
        print("* 良好的扩展性架构")
        print()
        
        print("=" * 70)
        print("下一步操作")
        print("=" * 70)
        print()
        print("1. 安装依赖（如果尚未安装）:")
        print("   python install.py")
        print()
        print("2. 查看详细帮助:")
        print("   python main.py --help")
        print()
        print("3. 查看使用示例:")
        print("   查看 examples.txt 文件")
        print()
        print("4. 快速开始:")
        print("   python main.py -t example.com -m dns,whois")
        print()
        
    except Exception as e:
        print(f"演示出错: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
