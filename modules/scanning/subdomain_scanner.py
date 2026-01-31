"""
子域名扫描器
支持暴力破解、搜索引擎、证书透明度等多种方式
"""

import dns.resolver
import dns.zone
import requests
import json
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.scanning.base_scanner import BaseScanner


class SubdomainScanner(BaseScanner):
    """子域名扫描器"""
    
    def __init__(self, config, logger=None):
        super().__init__(config, logger)
        self.description = "子域名扫描器"
        
        # 常用子域名字典
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 
            'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video', 
            'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 
            'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 
            'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info', 'apps', 
            'download', 'remote', 'db', 'forums', 'store', 'relay', 'files', 'newsletter', 
            'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4'
        ]
        
        # 搜索引擎API（需要API密钥的可选）
        self.search_engines = [
            self.search_crt_sh,
            self.search_certspotter,
            self.search_hackertarget,
            self.search_threatcrowd
        ]
    
    def scan(self, domain, timeout=5, wordlist=None):
        """
        扫描子域名
        
        Args:
            domain: 目标域名
            timeout: 超时时间
            wordlist: 自定义字典文件
        
        Returns:
            dict: 扫描结果
        """
        if not self.is_valid_target(domain):
            return self.format_result(False, error="无效的目标域名")
        
        self.log_info(f"开始扫描子域名: {domain}")
        
        results = {
            'domain': domain,
            'subdomains': [],
            'methods': {}
        }
        
        try:
            # 1. DNS区域传输（如果可能）
            self.log_info("尝试DNS区域传输...")
            zone_subdomains = self.dns_zone_transfer(domain, timeout)
            if zone_subdomains:
                results['subdomains'].extend(zone_subdomains)
                results['methods']['zone_transfer'] = len(zone_subdomains)
                self.log_info(f"通过区域传输发现 {len(zone_subdomains)} 个子域名")
            
            # 2. 搜索引擎和证书透明度
            self.log_info("从搜索引擎和证书透明度收集...")
            search_subdomains = self.search_subdomains(domain, timeout)
            if search_subdomains:
                results['subdomains'].extend(search_subdomains)
                results['methods']['search_engines'] = len(search_subdomains)
                self.log_info(f"通过搜索引擎发现 {len(search_subdomains)} 个子域名")
            
            # 3. 字典暴力破解
            if self.config.get('subdomain', {}).get('brute_force', True):
                self.log_info("开始字典暴力破解...")
                brute_subdomains = self.brute_force_subdomains(domain, timeout, wordlist)
                if brute_subdomains:
                    results['subdomains'].extend(brute_subdomains)
                    results['methods']['brute_force'] = len(brute_subdomains)
                    self.log_info(f"通过暴力破解发现 {len(brute_subdomains)} 个子域名")
            
            # 去重并排序
            unique_subdomains = list(set(results['subdomains']))
            
            # 验证子域名是否有效
            valid_subdomains = []
            for subdomain in unique_subdomains:
                if self.verify_subdomain(subdomain, timeout):
                    valid_subdomains.append(subdomain)
            
            results['subdomains'] = sorted(valid_subdomains)
            results['total_found'] = len(valid_subdomains)
            
            self.log_info(f"扫描完成，发现 {len(valid_subdomains)} 个有效子域名")
            
            return self.format_result(True, results)
            
        except Exception as e:
            self.log_error(f"扫描子域名时出错: {str(e)}")
            return self.format_result(False, error=str(e))
    
    def dns_zone_transfer(self, domain, timeout):
        """
        尝试DNS区域传输
        
        Args:
            domain: 域名
            timeout: 超时时间
        
        Returns:
            list: 子域名列表
        """
        subdomains = []
        
        try:
            # 获取NS记录
            answers = dns.resolver.resolve(domain, 'NS')
            ns_servers = [str(answer) for answer in answers]
            
            for ns in ns_servers:
                try:
                    # 尝试区域传输
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, lifetime=timeout))
                    names = zone.nodes.keys()
                    for name in names:
                        full_domain = f"{name}.{domain}"
                        if full_domain != domain:
                            subdomains.append(full_domain)
                except:
                    continue
        except:
            pass
        
        return list(set(subdomains))
    
    def search_subdomains(self, domain, timeout):
        """
        从各种来源搜索子域名
        
        Args:
            domain: 域名
            timeout: 超时时间
        
        Returns:
            list: 子域名列表
        """
        subdomains = []
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_engine = {}
            
            for engine in self.search_engines:
                future = executor.submit(engine, domain, timeout)
                future_to_engine[future] = engine.__name__
            
            for future in as_completed(future_to_engine):
                engine_name = future_to_engine[future]
                try:
                    result = future.result()
                    if result:
                        subdomains.extend(result)
                        self.log_debug(f"从 {engine_name} 发现 {len(result)} 个子域名")
                except Exception as e:
                    self.log_debug(f"搜索引擎 {engine_name} 失败: {str(e)}")
        
        return list(set(subdomains))
    
    def search_crt_sh(self, domain, timeout):
        """从crt.sh搜索子域名"""
        subdomains = []
        
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = requests.get(url, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name and domain in name:
                        # 处理可能的多行结果
                        names = name.split('\n')
                        for n in names:
                            n = n.strip()
                            if n and n.endswith(domain) and '*' not in n:
                                subdomains.append(n)
        except Exception as e:
            self.log_debug(f"crt.sh 搜索失败: {str(e)}")
        
        return subdomains
    
    def search_certspotter(self, domain, timeout):
        """从CertSpotter搜索子域名"""
        subdomains = []
        
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            response = requests.get(url, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    dns_names = entry.get('dns_names', [])
                    for name in dns_names:
                        if domain in name and '*' not in name:
                            subdomains.append(name)
        except Exception as e:
            self.log_debug(f"CertSpotter 搜索失败: {str(e)}")
        
        return subdomains
    
    def search_hackertarget(self, domain, timeout):
        """从HackerTarget搜索子域名"""
        subdomains = []
        
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = requests.get(url, timeout=timeout)
            
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) > 0:
                            subdomain = parts[0].strip()
                            if subdomain and domain in subdomain:
                                subdomains.append(subdomain)
        except Exception as e:
            self.log_debug(f"HackerTarget 搜索失败: {str(e)}")
        
        return subdomains
    
    def search_threatcrowd(self, domain, timeout):
        """从ThreatCrowd搜索子域名"""
        subdomains = []
        
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            response = requests.get(url, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == '1':
                    subdomains_list = data.get('subdomains', [])
                    subdomains.extend(subdomains_list)
        except Exception as e:
            self.log_debug(f"ThreatCrowd 搜索失败: {str(e)}")
        
        return subdomains
    
    def brute_force_subdomains(self, domain, timeout, wordlist=None):
        """
        使用字典暴力破解子域名
        
        Args:
            domain: 域名
            timeout: 超时时间
            wordlist: 自定义字典文件
        
        Returns:
            list: 子域名列表
        """
        subdomains = []
        
        # 获取字典列表
        subdomain_list = self._get_wordlist(wordlist) if wordlist else self.common_subdomains
        
        # 线程池进行DNS查询
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {}
            
            for sub in subdomain_list:
                full_domain = f"{sub}.{domain}"
                future = executor.submit(self.verify_subdomain, full_domain, timeout)
                future_to_subdomain[future] = full_domain
            
            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    if future.result():
                        subdomains.append(subdomain)
                except:
                    continue
        
        return subdomains
    
    def verify_subdomain(self, subdomain, timeout):
        """
        验证子域名是否有效
        
        Args:
            subdomain: 子域名
            timeout: 超时时间
        
        Returns:
            bool: 是否有效
        """
        try:
            # 尝试解析A记录
            answers = dns.resolver.resolve(subdomain, 'A', lifetime=timeout)
            return len(answers) > 0
        except:
            try:
                # 尝试解析CNAME记录
                answers = dns.resolver.resolve(subdomain, 'CNAME', lifetime=timeout)
                return len(answers) > 0
            except:
                return False
    
    def _get_wordlist(self, wordlist_file):
        """
        从文件读取字典
        
        Args:
            wordlist_file: 字典文件路径
        
        Returns:
            list: 字典列表
        """
        try:
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return self.common_subdomains
