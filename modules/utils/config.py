"""
配置管理模块
负责加载和管理配置文件
"""

import yaml
import os
from pathlib import Path


def load_config(config_path=None):
    """
    加载配置文件
    
    Args:
        config_path: 配置文件路径，如果为None则使用默认路径
    
    Returns:
        dict: 配置字典
    """
    if config_path is None:
        # 默认配置文件路径
        config_path = Path(__file__).parent.parent.parent / 'config.yaml'
    
    if not os.path.exists(config_path):
        # 如果配置文件不存在，返回默认配置
        return get_default_config()
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        print(f"加载配置文件失败: {str(e)}")
        return get_default_config()


def get_default_config():
    """
    获取默认配置
    
    Returns:
        dict: 默认配置字典
    """
    return {
        'scan': {
            'default_threads': 30,
            'default_timeout': 5,
            'max_threads': 200,
            'retry_count': 3
        },
        'subdomain': {
            'wordlist_file': 'data/subdomains.txt',
            'brute_force': True,
            'search_engines': True,
            'certificate_transparency': True,
            'dns_servers': ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        },
        'port': {
            'top_ports': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443],
            'common_ports': [80, 443, 8000, 8080, 8443, 8888],
            'all_ports': '1-65535',
            'scan_type': 'syn'
        },
        'service': {
            'banner_grabbing': True,
            'service_detection': True,
            'os_detection': False,
            'version_detection': True
        },
        'whois': {
            'timeout': 10,
            'use_cache': True,
            'cache_ttl': 86400
        },
        'dns': {
            'record_types': ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR'],
            'dns_servers': ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        },
        'directory': {
            'wordlist_file': 'data/directory.txt',
            'extensions': ['.php', '.asp', '.aspx', '.jsp', '.html', '.js', '.txt', '.bak'],
            'status_codes': [200, 204, 301, 302, 307, 403, 401],
            'recursive': False,
            'recursion_depth': 2
        },
        'vulnerability': {
            'scan_level': 'normal',
            'test_injection': True,
            'test_xss': True,
            'test_sqli': True,
            'test_command_injection': False
        },
        'ssl': {
            'check_expiry': True,
            'check_cipher': True,
            'check_certificate_chain': True,
            'alert_days_before': 30
        },
        'network': {
            'traceroute': True,
            'ping_sweep': False,
            'os_fingerprinting': False,
            'max_hops': 30
        },
        'api': {
            'enabled': True,
            'host': '0.0.0.0',
            'port': 8000,
            'debug': False,
            'cors_enabled': True
        },
        'report': {
            'template_dir': 'templates',
            'include_charts': True,
            'include_recommendations': True,
            'author': '网络安全团队',
            'company': '安全实验室'
        },
        'logging': {
            'level': 'INFO',
            'file': 'logs/recon-tool.log',
            'max_size': '10MB',
            'backup_count': 5
        },
        'proxy': {
            'enabled': False,
            'http': '',
            'https': ''
        },
        'user_agents': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        ]
    }


def save_config(config, config_path):
    """
    保存配置到文件
    
    Args:
        config: 配置字典
        config_path: 配置文件路径
    """
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        return True
    except Exception as e:
        print(f"保存配置文件失败: {str(e)}")
        return False


def merge_config(default_config, user_config):
    """
    合并用户配置和默认配置
    
    Args:
        default_config: 默认配置
        user_config: 用户配置
    
    Returns:
        dict: 合并后的配置
    """
    merged = default_config.copy()
    
    def merge_dict(d1, d2):
        for key, value in d2.items():
            if key in d1 and isinstance(d1[key], dict) and isinstance(value, dict):
                merge_dict(d1[key], value)
            else:
                d1[key] = value
    
    merge_dict(merged, user_config)
    return merged


# 配置验证函数
def validate_config(config):
    """
    验证配置的有效性
    
    Args:
        config: 配置字典
    
    Returns:
        tuple: (bool, str) - (是否有效, 错误信息)
    """
    required_sections = ['scan', 'subdomain', 'port', 'service']
    
    for section in required_sections:
        if section not in config:
            return False, f"缺少必要的配置段: {section}"
    
    # 验证线程数
    threads = config.get('scan', {}).get('default_threads', 30)
    if not isinstance(threads, int) or threads < 1 or threads > 1000:
        return False, "线程数必须在1-1000之间"
    
    # 验证超时时间
    timeout = config.get('scan', {}).get('default_timeout', 5)
    if not isinstance(timeout, int) or timeout < 1 or timeout > 300:
        return False, "超时时间必须在1-300秒之间"
    
    return True, "配置有效"
