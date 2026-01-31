"""
服务识别扫描器
识别开放端口上运行的服务类型和版本
"""

import socket
import re
import time
from concurrent.futures import ThreadPoolExecutor
from modules.scanning.base_scanner import BaseScanner


class ServiceScanner(BaseScanner):
    """服务识别扫描器"""
    
    def __init__(self, config, logger=None):
        super().__init__(config, logger)
        self.description = "服务识别扫描器"
        
        # 服务特征数据库
        self.service_signatures = {
            'FTP': {
                'ports': [21],
                'banners': [
                    r'220.*FTP',
                    r'vsFTPd',
                    r'ProFTPD',
                    r'Microsoft FTP Service'
                ],
                'probes': [b'\r\n'],
                'responses': []
            },
            'SSH': {
                'ports': [22],
                'banners': [
                    r'SSH-\d\.\d-',
                    r'OpenSSH_[\d\.]+',
                    r'SSH-2\.0-'
                ],
                'probes': [],
                'responses': []
            },
            'Telnet': {
                'ports': [23, 2323],
                'banners': [
                    r'\xff\xfb\x01',
                    r'login:',
                    r'Password:',
                    r'Welcome to'
                ],
                'probes': [b'\r\n'],
                'responses': []
            },
            'SMTP': {
                'ports': [25, 587, 465],
                'banners': [
                    r'220.*ESMTP',
                    r'220.*SMTP',
                    r'Postfix',
                    r'Exim',
                    r'Sendmail'
                ],
                'probes': [b'EHLO test\r\n'],
                'responses': []
            },
            'DNS': {
                'ports': [53],
                'banners': [],
                'probes': [b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03'],
                'responses': []
            },
            'HTTP': {
                'ports': [80, 8000, 8080, 8888],
                'banners': [
                    r'HTTP/\d\.\d',
                    r'Server:.*Apache',
                    r'Server:.*nginx',
                    r'Server:.*IIS'
                ],
                'probes': [b'HEAD / HTTP/1.0\r\n\r\n', b'GET / HTTP/1.0\r\n\r\n'],
                'responses': []
            },
            'HTTPS': {
                'ports': [443, 8443],
                'banners': [],
                'probes': [],
                'responses': []
            },
            'POP3': {
                'ports': [110],
                'banners': [
                    r'\+OK.*POP3',
                    r'\+OK.*pop3'
                ],
                'probes': [],
                'responses': []
            },
            'IMAP': {
                'ports': [143, 993],
                'banners': [
                    r'\* OK.*IMAP',
                    r'\* OK.*imap'
                ],
                'probes': [],
                'responses': []
            },
            'MySQL': {
                'ports': [3306],
                'banners': [
                    r'\x5b\x00\x00\x00\x0a'
                ],
                'probes': [],
                'responses': []
            },
            'PostgreSQL': {
                'ports': [5432],
                'banners': [],
                'probes': [],
                'responses': []
            },
            'RDP': {
                'ports': [3389],
                'banners': [
                    r'\x03\x00\x00'
                ],
                'probes': [],
                'responses': []
            },
            'VNC': {
                'ports': [5900, 5901],
                'banners': [
                    r'RFB \d{3}\.\d{3}'
                ],
                'probes': [],
                'responses': []
            }
        }
    
    def scan(self, target, timeout=5, port_data=None):
        """
        识别目标服务
        
        Args:
            target: 目标IP或域名
            timeout: 超时时间
            port_data: 端口数据，格式: [{'port': 80, 'state': 'open'}, ...]
        
        Returns:
            dict: 服务识别结果
        """
        if not self.is_valid_target(target):
            return self.format_result(False, error="无效的目标")
        
        self.log_info(f"开始识别 {target} 的服务")
        
        results = {
            'target': target,
            'services': [],
            'os_guess': None,
            'total_identified': 0
        }
        
        try:
            if not port_data:
                # 如果没有提供端口数据，先进行端口扫描
                from modules.scanning.port_scanner import PortScanner
                port_scanner = PortScanner(self.config, self.logger)
                port_result = port_scanner.scan(target, timeout)
                
                if port_result['success']:
                    port_data = port_result['data']['open_ports']
                else:
                    return self.format_result(False, error="无法获取端口信息")
            
            # 识别每个端口的服务
            services = self._identify_services(target, port_data, timeout)
            results['services'] = services
            results['total_identified'] = len(services)
            
            # 操作系统指纹识别（简化版）
            if self.config.get('service', {}).get('os_detection', False):
                results['os_guess'] = self._detect_os(target, services)
            
            self.log_info(f"服务识别完成，识别出 {len(services)} 个服务")
            
            return self.format_result(True, results)
            
        except Exception as e:
            self.log_error(f"服务识别时出错: {str(e)}")
            return self.format_result(False, error=str(e))
    
    def _identify_services(self, target, port_data, timeout):
        """
        识别端口服务
        
        Args:
            target: 目标IP或域名
            port_data: 端口数据
            timeout: 超时时间
        
        Returns:
            list: 服务信息列表
        """
        services = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {}
            
            for port_info in port_data:
                port = port_info['port']
                future = executor.submit(self._identify_service, target, port, timeout)
                future_to_port[future] = port
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    service_info = future.result()
                    if service_info:
                        services.append(service_info)
                        self.log_debug(f"端口 {port} 识别为 {service_info['service']}")
                except Exception as e:
                    self.log_debug(f"识别端口 {port} 服务失败: {str(e)}")
        
        return services
    
    def _identify_service(self, target, port, timeout):
        """
        识别单个端口的服务
        
        Args:
            target: 目标IP或域名
            port: 端口号
            timeout: 超时时间
        
        Returns:
            dict: 服务信息
        """
        service_info = {
            'port': port,
            'service': 'unknown',
            'version': None,
            'banner': None,
            'cpe': None,
            'confidence': 0
        }
        
        try:
            # 首先根据端口猜测服务
            guessed_service = self._guess_service_by_port(port)
            
            # 连接并获取banner
            banner = self._grab_banner(target, port, timeout)
            service_info['banner'] = banner
            
            if banner:
                # 根据banner识别服务
                identified_service = self._identify_by_banner(banner, port)
                if identified_service:
                    service_info['service'] = identified_service['name']
                    service_info['version'] = identified_service.get('version')
                    service_info['cpe'] = identified_service.get('cpe')
                    service_info['confidence'] = identified_service.get('confidence', 80)
                else:
                    # 如果无法识别，使用端口猜测
                    service_info['service'] = guessed_service
                    service_info['confidence'] = 30
            else:
                # 发送探测请求
                identified_service = self._probe_service(target, port, timeout)
                if identified_service:
                    service_info.update(identified_service)
                else:
                    service_info['service'] = guessed_service
                    service_info['confidence'] = 20
            
        except Exception as e:
            self.log_debug(f"识别端口 {port} 失败: {str(e)}")
            service_info['service'] = self._guess_service_by_port(port)
            service_info['confidence'] = 10
        
        return service_info
    
    def _guess_service_by_port(self, port):
        """
        根据端口猜测服务
        
        Args:
            port: 端口号
        
        Returns:
            str: 服务名称
        """
        port_service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
        }
        return port_service_map.get(port, f'unknown-{port}')
    
    def _grab_banner(self, target, port, timeout):
        """
        抓取服务banner
        
        Args:
            target: 目标IP或域名
            port: 端口号
            timeout: 超时时间
        
        Returns:
            str: banner字符串
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            result = sock.connect_ex((target, port))
            if result != 0:
                sock.close()
                return None
            
            # 尝试接收banner
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                return banner.strip()
            except:
                # 如果没有banner，发送探测请求
                for service, sig in self.service_signatures.items():
                    if port in sig['ports'] and sig['probes']:
                        for probe in sig['probes']:
                            try:
                                sock.send(probe)
                                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                                if banner:
                                    sock.close()
                                    return banner.strip()
                            except:
                                continue
            
            sock.close()
            return None
            
        except Exception:
            return None
    
    def _identify_by_banner(self, banner, port):
        """
        根据banner识别服务
        
        Args:
            banner: banner字符串
            port: 端口号
        
        Returns:
            dict: 识别结果
        """
        for service, sig in self.service_signatures.items():
            if port in sig['ports']:
                for pattern in sig['banners']:
                    try:
                        if re.search(pattern, banner, re.IGNORECASE):
                            version = self._extract_version(banner, service)
                            return {
                                'name': service,
                                'version': version,
                                'cpe': self._generate_cpe(service, version),
                                'confidence': 90
                            }
                    except:
                        continue
        
        return None
    
    def _probe_service(self, target, port, timeout):
        """
        通过探测请求识别服务
        
        Args:
            target: 目标IP或域名
            port: 端口号
            timeout: 超时时间
        
        Returns:
            dict: 服务信息
        """
        for service, sig in self.service_signatures.items():
            if port in sig['ports'] and sig['probes']:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    
                    if sock.connect_ex((target, port)) == 0:
                        for probe in sig['probes']:
                            sock.send(probe)
                            response = sock.recv(1024).decode('utf-8', errors='ignore')
                            
                            if response:
                                for pattern in sig['banners']:
                                    if re.search(pattern, response, re.IGNORECASE):
                                        version = self._extract_version(response, service)
                                        sock.close()
                                        return {
                                            'service': service,
                                            'version': version,
                                            'banner': response,
                                            'cpe': self._generate_cpe(service, version),
                                            'confidence': 85
                                        }
                    
                    sock.close()
                except:
                    continue
        
        return None
    
    def _extract_version(self, banner, service):
        """
        从banner中提取版本信息
        
        Args:
            banner: banner字符串
            service: 服务名称
        
        Returns:
            str: 版本号
        """
        version_patterns = {
            'SSH': r'OpenSSH_([\d\.]+p?[\d]?)',
            'FTP': r'([\d\.]+)',
            'Apache': r'Apache/([\d\.]+)',
            'nginx': r'nginx/([\d\.]+)',
            'MySQL': r'([\d\.]+)',
            'SMTP': r'([\d\.]+)'
        }
        
        pattern = version_patterns.get(service, r'([\d\.]+)')
        
        try:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        except:
            pass
        
        return None
    
    def _generate_cpe(self, service, version):
        """
        生成CPE（通用平台枚举）
        
        Args:
            service: 服务名称
            version: 版本号
        
        Returns:
            str: CPE字符串
        """
        service_cpe_map = {
            'SSH': 'cpe:/a:openssh:openssh',
            'Apache': 'cpe:/a:apache:http_server',
            'nginx': 'cpe:/a:nginx:nginx',
            'MySQL': 'cpe:/a:mysql:mysql',
            'FTP': 'cpe:/a:vsftpd:vsftpd',
            'SMTP': 'cpe:/a:postfix:postfix'
        }
        
        cpe = service_cpe_map.get(service, f'cpe:/a:unknown:{service.lower()}')
        
        if version:
            cpe += f':{version}'
        
        return cpe
    
    def _detect_os(self, target, services):
        """
        简单的操作系统指纹识别
        
        Args:
            target: 目标IP
            services: 服务列表
        
        Returns:
            str: 操作系统猜测
        """
        os_hints = []
        
        for service in services:
            banner = service.get('banner', '')
            service_name = service.get('service', '')
            
            if 'Microsoft' in banner or 'IIS' in banner:
                os_hints.append('Windows')
            elif 'OpenSSH' in banner and 'Ubuntu' in banner:
                os_hints.append('Linux-Ubuntu')
            elif 'OpenSSH' in banner:
                os_hints.append('Linux')
            elif 'Apache' in banner and 'CentOS' in banner:
                os_hints.append('Linux-CentOS')
            elif 'nginx' in banner:
                os_hints.append('Linux')
            elif service_name == 'RDP':
                os_hints.append('Windows')
        
        if os_hints:
            # 返回最常见的猜测
            return max(set(os_hints), key=os_hints.count)
        
        return 'unknown'
