"""
DNS记录扫描器
获取域名的各种DNS记录
"""

import dns.resolver
import dns.reversename
import dns.zone
import socket
from modules.scanning.base_scanner import BaseScanner


class DNSScanner(BaseScanner):
    """DNS记录扫描器"""
    
    def __init__(self, config, logger=None):
        super().__init__(config, logger)
        self.description = "DNS记录扫描器"
        
        # DNS记录类型
        self.record_types = config.get('dns', {}).get('record_types', 
            ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR'])
        
        # DNS服务器
        self.dns_servers = config.get('dns', {}).get('dns_servers', 
            ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'])
    
    def scan(self, target, timeout=5, wordlist=None):
        """
        扫描DNS记录
        
        Args:
            target: 目标域名
            timeout: 超时时间
            wordlist: 额外的记录类型列表
        
        Returns:
            dict: DNS记录结果
        """
        if not self.is_valid_target(target):
            return self.format_result(False, error="无效的目标域名")
        
        self.log_info(f"开始扫描DNS记录: {target}")
        
        results = {
            'domain': target,
            'records': {},
            'total_records': 0
        }
        
        try:
            # 设置DNS解析器超时
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            # 如果指定了DNS服务器，使用它们
            if self.dns_servers:
                resolver.nameservers = self.dns_servers
            
            # 查询各种DNS记录
            for record_type in self.record_types:
                try:
                    records = self._query_dns_record(resolver, target, record_type)
                    if records:
                        results['records'][record_type] = records
                        results['total_records'] += len(records)
                        self.log_debug(f"发现 {record_type} 记录: {len(records)} 条")
                except Exception as e:
                    self.log_debug(f"查询 {record_type} 记录失败: {str(e)}")
                    continue
            
            # 额外查询
            if self.config.get('dns', {}).get('zone_transfer', True):
                zone_records = self._attempt_zone_transfer(target)
                if zone_records:
                    results['zone_transfer'] = zone_records
            
            self.log_info(f"DNS扫描完成，共发现 {results['total_records']} 条记录")
            
            return self.format_result(True, results)
            
        except Exception as e:
            self.log_error(f"DNS扫描时出错: {str(e)}")
            return self.format_result(False, error=str(e))
    
    def _query_dns_record(self, resolver, domain, record_type):
        """
        查询特定类型的DNS记录
        
        Args:
            resolver: DNS解析器
            domain: 域名
            record_type: 记录类型
        
        Returns:
            list: 记录列表
        """
        records = []
        
        try:
            answers = resolver.resolve(domain, record_type)
            
            for answer in answers:
                record_data = {
                    'value': str(answer),
                    'ttl': answers.ttl
                }
                
                # 特殊处理不同类型的记录
                if record_type == 'MX':
                    record_data['priority'] = answer.preference
                    record_data['exchange'] = str(answer.exchange)
                elif record_type == 'SOA':
                    record_data['primary_ns'] = str(answer.mname)
                    record_data['email'] = str(answer.rname)
                    record_data['serial'] = answer.serial
                    record_data['refresh'] = answer.refresh
                    record_data['retry'] = answer.retry
                    record_data['expire'] = answer.expire
                    record_data['minimum'] = answer.minimum
                elif record_type == 'SRV':
                    record_data['priority'] = answer.priority
                    record_data['weight'] = answer.weight
                    record_data['port'] = answer.port
                    record_data['target'] = str(answer.target)
                
                records.append(record_data)
            
        except dns.resolver.NXDOMAIN:
            self.log_debug(f"域名不存在: {domain}")
        except dns.resolver.NoAnswer:
            self.log_debug(f"没有 {record_type} 记录: {domain}")
        except Exception as e:
            self.log_debug(f"查询 {record_type} 记录出错: {str(e)}")
        
        return records
    
    def _attempt_zone_transfer(self, domain):
        """
        尝试DNS区域传输
        
        Args:
            domain: 域名
        
        Returns:
            dict: 区域传输结果
        """
        zone_data = {
            'success': False,
            'records': {},
            'nameservers': []
        }
        
        try:
            # 获取NS记录
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, 'NS')
            
            ns_servers = [str(answer) for answer in answers]
            zone_data['nameservers'] = ns_servers
            
            for ns in ns_servers:
                try:
                    # 尝试区域传输
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                    
                    zone_data['success'] = True
                    zone_data['source_ns'] = ns
                    
                    # 提取所有记录
                    for name, node in zone.nodes.items():
                        rdatasets = node.rdatasets
                        for rdataset in rdatasets:
                            record_type = dns.rdatatype.to_text(rdataset.rdtype)
                            if record_type not in zone_data['records']:
                                zone_data['records'][record_type] = []
                            
                            for rdata in rdataset:
                                zone_data['records'][record_type].append(str(rdata))
                    
                    self.log_info(f"成功从 {ns} 获取区域传输数据")
                    break
                    
                except Exception as e:
                    self.log_debug(f"从 {ns} 区域传输失败: {str(e)}")
                    continue
        
        except Exception as e:
            self.log_debug(f"区域传输尝试失败: {str(e)}")
        
        return zone_data


class WhoisScanner(BaseScanner):
    """WHOIS查询扫描器"""
    
    def __init__(self, config, logger=None):
        super().__init__(config, logger)
        self.description = "WHOIS信息查询器"
        self.timeout = config.get('whois', {}).get('timeout', 10)
    
    def scan(self, target, timeout=None, wordlist=None):
        """
        查询WHOIS信息
        
        Args:
            target: 目标域名或IP
            timeout: 超时时间
            wordlist: 未使用
        
        Returns:
            dict: WHOIS信息
        """
        if not self.is_valid_target(target):
            return self.format_result(False, error="无效的目标")
        
        timeout = timeout or self.timeout
        self.log_info(f"查询WHOIS信息: {target}")
        
        results = {
            'target': target,
            'domain_name': None,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'status': [],
            'emails': [],
            'whois_server': None,
            'raw_data': None
        }
        
        try:
            # 尝试使用python-whois库
            try:
                import whois
                w = whois.whois(target)
                
                results['domain_name'] = w.get('domain_name')
                results['registrar'] = w.get('registrar')
                results['creation_date'] = str(w.get('creation_date', ''))
                results['expiration_date'] = str(w.get('expiration_date', ''))
                results['updated_date'] = str(w.get('updated_date', ''))
                results['name_servers'] = w.get('name_servers', [])
                results['status'] = w.get('status', [])
                results['emails'] = w.get('emails', [])
                results['whois_server'] = w.get('whois_server')
                
            except ImportError:
                self.log_warning("python-whois库未安装，使用备用方法")
                results['raw_data'] = self._whois_query(target)
            
            self.log_info(f"WHOIS查询完成")
            
            return self.format_result(True, results)
            
        except Exception as e:
            self.log_error(f"WHOIS查询时出错: {str(e)}")
            return self.format_result(False, error=str(e))
    
    def _whois_query(self, target):
        """
        简单的WHOIS查询实现
        
        Args:
            target: 目标域名或IP
        
        Returns:
            str: WHOIS原始数据
        """
        import socket
        
        # WHOIS服务器列表
        whois_servers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'cn': 'whois.cnnic.cn',
            'io': 'whois.nic.io'
        }
        
        try:
            # 获取域名后缀
            if '.' in target:
                domain_suffix = target.split('.')[-1].lower()
                whois_server = whois_servers.get(domain_suffix, 'whois.iana.org')
            else:
                whois_server = 'whois.iana.org'
            
            # 连接WHOIS服务器
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((whois_server, 43))
            
            # 发送查询
            s.send(f"{target}\r\n".encode())
            
            # 接收响应
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            
            s.close()
            return response.decode('utf-8', errors='ignore')
            
        except Exception as e:
            self.log_debug(f"WHOIS查询失败: {str(e)}")
            return None
