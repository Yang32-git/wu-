#!/usr/bin/env python3
"""
测试脚本 - 演示工具的基本功能
"""

import sys
import os
from modules.core.recon_engine import ReconEngine
from modules.utils.logger import setup_logger
from modules.utils.config import load_config

def test_basic_scan():
    """测试基本扫描功能"""
    print("测试基本扫描功能...")
    
    # 加载配置
    config = load_config()
    
    # 设置日志
    logger = setup_logger(verbose=True)
    
    # 创建扫描引擎
    engine = ReconEngine(config, logger)
    
    # 测试目标（使用测试域名）
    target = "example.com"
    modules = ['dns', 'whois', 'subdomain']
    
    print(f"扫描目标: {target}")
    print(f"扫描模块: {', '.join(modules)}")
    
    try:
        # 执行扫描
        result = engine.scan_target(target, modules, threads=10, timeout=3)
        
        print(f"\n扫描完成!")
        print(f"状态: {result.get('status')}")
        print(f"耗时: {result.get('duration')} 秒")
        
        # 显示结果
        if result.get('success', False):
            print("\n=== 扫描结果 ===")
            
            # DNS记录
            if 'dns' in result.get('results', {}):
                dns_result = result['results']['dns']
                if dns_result.get('success', False):
                    dns_data = dns_result.get('data', {})
                    print(f"\nDNS记录总数: {dns_data.get('total_records', 0)}")
                    records = dns_data.get('records', {})
                    for record_type, record_list in records.items():
                        print(f"  {record_type}: {len(record_list)} 条记录")
            
            # WHOIS信息
            if 'whois' in result.get('results', {}):
                whois_result = result['results']['whois']
                if whois_result.get('success', False):
                    whois_data = whois_result.get('data', {})
                    print(f"\nWHOIS信息:")
                    print(f"  域名: {whois_data.get('domain_name')}")
                    print(f"  注册商: {whois_data.get('registrar')}")
                    print(f"  创建日期: {whois_data.get('creation_date')}")
                    print(f"  过期日期: {whois_data.get('expiration_date')}")
            
            # 子域名
            if 'subdomain' in result.get('results', {}):
                subdomain_result = result['results']['subdomain']
                if subdomain_result.get('success', False):
                    subdomain_data = subdomain_result.get('data', {})
                    print(f"\n子域名总数: {subdomain_data.get('total_found', 0)}")
                    subdomains = subdomain_data.get('subdomains', [])
                    if subdomains:
                        print(f"  前5个子域名:")
                        for subdomain in subdomains[:5]:
                            print(f"    - {subdomain}")
        
        return True
        
    except Exception as e:
        print(f"扫描失败: {str(e)}")
        return False

def test_api_mode():
    """测试API模式"""
    print("\n测试API模式...")
    
    try:
        from modules.api.api_server import APIServer
        
        # 加载配置
        config = load_config()
        
        # 创建API服务器（不实际启动）
        api_server = APIServer(config, port=8888)
        
        print(f"API服务器创建成功")
        print(f"扫描器数量: {len(api_server.engine.scanners)}")
        
        # 获取扫描器信息
        scanner_info = api_server.engine.get_scanner_info()
        print(f"\n可用扫描器:")
        for name, info in scanner_info.items():
            print(f"  - {name}: {info.get('description')}")
        
        return True
        
    except Exception as e:
        print(f"API模式测试失败: {str(e)}")
        return False

def test_report_generation():
    """测试报告生成功能"""
    print("\n测试报告生成功能...")
    
    try:
        from modules.report.report_generator import ReportGenerator
        
        # 加载配置
        config = load_config()
        
        # 创建报告生成器
        report_gen = ReportGenerator(config)
        
        # 模拟扫描结果
        mock_results = {
            "example.com": {
                "target": "example.com",
                "status": "completed",
                "start_time": "2024-01-31 12:00:00",
                "end_time": "2024-01-31 12:02:30",
                "duration": 150,
                "modules": ["dns", "whois"],
                "results": {
                    "dns": {
                        "success": True,
                        "data": {
                            "domain": "example.com",
                            "total_records": 3,
                            "records": {
                                "A": [{"value": "93.184.216.34", "ttl": 86400}],
                                "MX": [{"value": "mx.example.com", "ttl": 3600}],
                                "NS": [{"value": "ns.example.com", "ttl": 86400}]
                            }
                        }
                    },
                    "whois": {
                        "success": True,
                        "data": {
                            "domain_name": "example.com",
                            "registrar": "Example Registrar",
                            "creation_date": "1995-08-14",
                            "expiration_date": "2024-08-13"
                        }
                    }
                }
            }
        }
        
        # 生成JSON报告
        json_file = "test_report.json"
        report_gen.generate_report(mock_results, json_file)
        
        if os.path.exists(json_file):
            print(f"JSON报告生成成功: {json_file}")
            
            # 读取并显示部分内容
            with open(json_file, 'r', encoding='utf-8') as f:
                import json
                report_data = json.load(f)
                print(f"报告包含 {len(report_data.get('targets', []))} 个目标")
                print(f"总体风险等级: {report_data.get('summary', {}).get('risk_level', 'unknown')}")
            
            # 清理测试文件
            os.unlink(json_file)
            return True
        else:
            print("JSON报告生成失败")
            return False
            
    except Exception as e:
        print(f"报告生成测试失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """主测试函数"""
    print("=" * 60)
    print("网络安全信息收集工具 - 功能测试")
    print("=" * 60)
    
    tests = [
        ("基本扫描功能", test_basic_scan),
        ("API模式", test_api_mode),
        ("报告生成", test_report_generation),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*60}")
        print(f"运行测试: {test_name}")
        print('='*60)
        
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} 测试通过")
            else:
                print(f"❌ {test_name} 测试失败")
        except Exception as e:
            print(f"❌ {test_name} 测试异常: {str(e)}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*60}")
    print(f"测试结果: {passed}/{total} 通过")
    print('='*60)
    
    if passed == total:
        print("🎉 所有测试通过！工具运行正常。")
        return 0
    else:
        print("⚠️  部分测试失败，请检查错误信息。")
        return 1

if __name__ == '__main__':
    sys.exit(main())
