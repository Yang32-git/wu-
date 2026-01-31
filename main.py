#!/usr/bin/env python3
"""
网络安全信息收集工具 - 主程序
支持多线程操作，提供API接口和报告生成功能
"""

import argparse
import sys
import os
from pathlib import Path
from modules.core.recon_engine import ReconEngine
from modules.api.api_server import APIServer
from modules.report.report_generator import ReportGenerator
from modules.utils.logger import setup_logger
from modules.utils.config import load_config


def main():
    parser = argparse.ArgumentParser(
        description='网络安全信息收集工具 - 全面的网络资产探测与漏洞检测',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  python main.py -t example.com -m subdomain,port,dns
  python main.py -t 192.168.1.0/24 -m port,vuln -o report.html
  python main.py --api --port 8080
  python tkinter_gui.py                    # 启动GUI界面
  python main.py -t example.com -m all --threads 50
        """
    )
    
    # 目标参数
    parser.add_argument('-t', '--target', help='目标域名或IP地址')
    parser.add_argument('-f', '--file', help='从文件读取目标列表')
    
    # 模块选择
    parser.add_argument('-m', '--modules', 
                       help='启用的模块 (subdomain,port,service,dns,whois,dir,vuln,ssl,network,all)',
                       default='all')
    
    # 性能参数
    parser.add_argument('--threads', type=int, default=30, help='线程数 (默认: 30)')
    parser.add_argument('--timeout', type=int, default=5, help='超时时间 (默认: 5秒)')
    
    # 输出参数
    parser.add_argument('-o', '--output', help='输出报告文件 (支持: html, pdf, json)')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    
    # 运行模式
    parser.add_argument('--api', action='store_true', help='启动API服务器模式')
    parser.add_argument('--api-port', type=int, default=8000, help='API服务器端口 (默认: 8000)'
    
    # 其他选项
    parser.add_argument('--config', help='配置文件路径')
    parser.add_argument('--wordlist', help='自定义字典文件路径')
    
    args = parser.parse_args()
    
    # 设置日志
    logger = setup_logger(verbose=args.verbose)
    
    # 加载配置
    config = load_config(args.config)
    
    # API服务器模式
    if args.api:
        logger.info(f"启动API服务器，端口: {args.api_port}")
        api_server = APIServer(config, args.api_port)
        api_server.start()
        return
    
    # 检查目标参数
    if not args.target and not args.file:
        parser.error("必须指定目标 (-t) 或目标文件 (-f)")
    
    # 初始化扫描引擎
    engine = ReconEngine(config, logger)
    
    # 解析目标
    targets = []
    if args.target:
        targets.append(args.target)
    if args.file:
        if os.path.exists(args.file):
            with open(args.file, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        else:
            logger.error(f"目标文件不存在: {args.file}")
            sys.exit(1)
    
    # 解析模块
    available_modules = {
        'subdomain': '子域名扫描',
        'port': '端口探测', 
        'service': '服务识别',
        'dns': 'DNS记录获取',
        'whois': 'WHOIS查询',
        'dir': '目录扫描',
        'vuln': '漏洞检测',
        'ssl': 'SSL证书分析',
        'network': '网络拓扑探测'
    }
    
    if args.modules.lower() == 'all':
        modules = list(available_modules.keys())
    else:
        modules = args.modules.split(',')
        modules = [m.strip() for m in modules if m.strip() in available_modules]
    
    if not modules:
        logger.error("未指定有效的扫描模块")
        sys.exit(1)
    
    logger.info(f"开始信息收集任务 - 目标: {len(targets)}个, 模块: {', '.join(modules)}")
    
    # 执行扫描
    results = {}
    for target in targets:
        logger.info(f"扫描目标: {target}")
        try:
            target_results = engine.scan_target(target, modules, args.threads, args.timeout, args.wordlist)
            results[target] = target_results
            logger.info(f"完成扫描: {target}")
        except Exception as e:
            logger.error(f"扫描 {target} 时出错: {str(e)}")
            results[target] = {'error': str(e)}
    
    # 生成报告
    if args.output:
        logger.info(f"生成报告: {args.output}")
        report_gen = ReportGenerator(config)
        try:
            report_gen.generate_report(results, args.output)
            logger.info(f"报告已生成: {args.output}")
        except Exception as e:
            logger.error(f"生成报告时出错: {str(e)}")
    
    logger.info("所有任务完成")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n操作被用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"程序执行错误: {str(e)}")
        sys.exit(1)
