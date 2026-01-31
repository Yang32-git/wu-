"""
SSL/TLS证书分析扫描器
分析SSL证书的安全性和配置
"""

import ssl
import socket
import datetime
from concurrent.futures import ThreadPoolExecutor
from modules.scanning.base_scanner import BaseScanner


class SSLScanner(BaseScanner):
    """SSL/TLS证书扫描器"""
    
    def __init__(self, config, logger=None):
        super().__init__(config, logger)
        self.description = "SSL/TLS证书分析器"
        
        # 检查配置
        self.check_expiry = config.get('ssl', {}).get('check_expiry', True)
        self.check_cipher = config.get('ssl', {}).get('check_cipher', True)
        self.check_certificate_chain = config.get('ssl', {}).get('check_certificate_chain', True)
        self.alert_days_before = config.get('ssl', {}).get('alert_days_before', 30)
    
    def scan(self, target, timeout=5, wordlist=None):
        """
        扫描SSL/TLS证书
        
        Args:
            target: 目标域名或IP
            timeout: 超时时间
            wordlist: 要检查的端口列表
        
        Returns:
            dict: SSL扫描结果
        """
        if not self.is_valid_target(target):
            return self.format_result(False, error="无效的目标")
        
        self.log_info(f"开始SSL/TLS证书分析: {target}")
        
        results = {
            'target': target,
            'certificates': [],
            'vulnerabilities': [],
            'warnings': [],
            'info': []
        }
        
        try:
            # 默认检查常见HTTPS端口
            ports = [443, 8443]
            if wordlist and isinstance(wordlist, list):
                ports = wordlist
            
            # 检查每个端口
            for port in ports:
                try:
                    cert_info = self._analyze_certificate(target, port, timeout)
                    if cert_info:
                        results['certificates'].append(cert_info)
                        
                        # 检查证书问题
                        if self.check_expiry:
                            expiry_issues = self._check_certificate_expiry(cert_info)
                            results['vulnerabilities'].extend(expiry_issues.get('vulnerabilities', []))
                            results['warnings'].extend(expiry_issues.get('warnings', []))
                        
                        # 检查证书链
                        if self.check_certificate_chain:
                            chain_issues = self._check_certificate_chain(cert_info)
                            results['warnings'].extend(chain_issues.get('warnings', []))
                
                except Exception as e:
                    self.log_debug(f"端口 {port} SSL检查失败: {str(e)}")
                    continue
            
            # 检查SSL/TLS配置
            ssl_config_issues = self._check_ssl_configuration(target)
            results['vulnerabilities'].extend(ssl_config_issues.get('vulnerabilities', []))
            results['warnings'].extend(ssl_config_issues.get('warnings', []))
            
            self.log_info(f"SSL扫描完成，发现 {len(results['certificates'])} 个证书")
            
            return self.format_result(True, results)
            
        except Exception as e:
            self.log_error(f"SSL扫描时出错: {str(e)}")
            return self.format_result(False, error=str(e))
    
    def _analyze_certificate(self, hostname, port, timeout):
        """
        分析SSL证书
        
        Args:
            hostname: 主机名
            port: 端口
            timeout: 超时时间
        
        Returns:
            dict: 证书信息
        """
        try:
            # 创建SSL连接
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if not cert:
                        return None
                    
                    # 解析证书信息
                    cert_info = {
                        'port': port,
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'subjectAltName': cert.get('subjectAltName', [])
                    }
                    
                    # 计算剩余天数
                    if cert_info['notAfter']:
                        expiry_date = datetime.datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_remaining = (expiry_date - datetime.datetime.now()).days
                        cert_info['days_remaining'] = days_remaining
                        cert_info['expiry_date'] = expiry_date.isoformat()
                    
                    # 获取使用的加密套件
                    cipher = ssock.cipher()
                    cert_info['cipher'] = {
                        'name': cipher[0],
                        'protocol': cipher[1],
                        'bits': cipher[2]
                    }
                    
                    return cert_info
        
        except Exception as e:
            self.log_debug(f"证书分析失败 {hostname}:{port}: {str(e)}")
            return None
    
    def _check_certificate_expiry(self, cert_info):
        """
        检查证书过期
        
        Args:
            cert_info: 证书信息
        
        Returns:
            dict: 过期问题
        """
        issues = {'vulnerabilities': [], 'warnings': []}
        
        try:
            days_remaining = cert_info.get('days_remaining', 0)
            
            if days_remaining < 0:
                issues['vulnerabilities'].append({
                    'type': 'Expired Certificate',
                    'description': f"证书已过期 {abs(days_remaining)} 天",
                    'severity': 'critical',
                    'port': cert_info['port'],
                    'recommendation': '立即更新SSL证书'
                })
            elif days_remaining <= self.alert_days_before:
                issues['warnings'].append({
                    'type': 'Certificate Expiring Soon',
                    'description': f"证书将在 {days_remaining} 天后过期",
                    'severity': 'medium',
                    'port': cert_info['port'],
                    'recommendation': f'准备在 {days_remaining} 天内更新证书'
                })
        
        except Exception as e:
            self.log_debug(f"证书过期检查失败: {str(e)}")
        
        return issues
    
    def _check_certificate_chain(self, cert_info):
        """
        检查证书链
        
        Args:
            cert_info: 证书信息
        
        Returns:
            dict: 证书链问题
        """
        issues = {'warnings': []}
        
        try:
            # 检查是否为自签名证书
            subject = cert_info.get('subject', {})
            issuer = cert_info.get('issuer', {})
            
            if subject.get('commonName') == issuer.get('commonName'):
                issues['warnings'].append({
                    'type': 'Self-Signed Certificate',
                    'description': '使用自签名证书',
                    'severity': 'medium',
                    'port': cert_info['port'],
                    'recommendation': '使用受信任的CA颁发的证书'
                })
        
        except Exception as e:
            self.log_debug(f"证书链检查失败: {str(e)}")
        
        return issues
    
    def _check_ssl_configuration(self, hostname):
        """
        检查SSL/TLS配置
        
        Args:
            hostname: 主机名
        
        Returns:
            dict: 配置问题
        """
        issues = {'vulnerabilities': [], 'warnings': []}
        
        # 检查SSL版本支持
        vulnerable_protocols = []
        
        protocols = [
            (ssl.PROTOCOL_TLSv1, 'TLS 1.0'),
            (ssl.PROTOCOL_TLSv1_1, 'TLS 1.1')
        ]
        
        for protocol, name in protocols:
            try:
                context = ssl.SSLContext(protocol)
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        vulnerable_protocols.append(name)
            except:
                continue
        
        if vulnerable_protocols:
            issues['vulnerabilities'].append({
                'type': 'Outdated SSL/TLS Protocol',
                'description': f"支持不安全的协议: {', '.join(vulnerable_protocols)}",
                'severity': 'high',
                'recommendation': '禁用TLS 1.0和TLS 1.1，仅使用TLS 1.2及以上版本'
            })
        
        return issues


class NetworkScanner(BaseScanner):
    """网络拓扑扫描器"""
    
    def __init__(self, config, logger=None):
        super().__init__(config, logger)
        self.description = "网络拓扑扫描器"
        
        # 网络扫描配置
        self.traceroute_enabled = config.get('network', {}).get('traceroute', True)
        self.ping_sweep = config.get('network', {}).get('ping_sweep', False)
        self.os_fingerprinting = config.get('network', {}).get('os_fingerprinting', False)
        self.max_hops = config.get('network', {}).get('max_hops', 30)
    
    def scan(self, target, timeout=5, wordlist=None):
        """
        执行网络拓扑扫描
        
        Args:
            target: 目标IP或域名
            timeout: 超时时间
            wordlist: 未使用
        
        Returns:
            dict: 网络扫描结果
        """
        if not self.is_valid_target(target):
            return self.format_result(False, error="无效的目标")
        
        self.log_info(f"开始网络拓扑扫描: {target}")
        
        results = {
            'target': target,
            'traceroute': None,
            'network_info': {},
            'os_guess': None
        }
        
        try:
            # 执行路由追踪
            if self.traceroute_enabled:
                self.log_info("执行路由追踪...")
                traceroute_result = self._perform_traceroute(target, timeout)
                results['traceroute'] = traceroute_result
            
            # 获取网络信息
            results['network_info'] = self._get_network_info(target)
            
            # 操作系统指纹识别
            if self.os_fingerprinting:
                self.log_info("进行操作系统指纹分析...")
                results['os_guess'] = self._detect_os(target, timeout)
            
            self.log_info(f"网络拓扑扫描完成")
            
            return self.format_result(True, results)
            
        except Exception as e:
            self.log_error(f"网络扫描时出错: {str(e)}")
            return self.format_result(False, error=str(e))
    
    def _perform_traceroute(self, target, timeout):
        """
        执行路由追踪
        
        Args:
            target: 目标IP或域名
            timeout: 超时时间
        
        Returns:
            dict: 路由信息
        """
        try:
            import platform
            import subprocess
            
            # 根据操作系统选择traceroute命令
            if platform.system().lower() == 'windows':
                cmd = ['tracert', '-d', '-w', str(timeout * 1000), target]
            else:
                cmd = ['traceroute', '-n', '-w', str(timeout), '-m', str(self.max_hops), target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * self.max_hops)
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'output': result.stdout,
                    'hops': self._parse_traceroute_output(result.stdout)
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr
                }
        
        except Exception as e:
            self.log_debug(f"路由追踪失败: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _parse_traceroute_output(self, output):
        """
        解析traceroute输出
        
        Args:
            output: traceroute输出
        
        Returns:
            list: 跳数信息
        """
        hops = []
        
        try:
            lines = output.split('\n')
            for line in lines:
                if line.strip() and any(char.isdigit() for char in line[:5]):
                    hops.append(line.strip())
        except:
            pass
        
        return hops
    
    def _get_network_info(self, target):
        """
        获取网络信息
        
        Args:
            target: 目标IP或域名
        
        Returns:
            dict: 网络信息
        """
        info = {
            'hostname': None,
            'ip_address': None,
            'reverse_dns': None
        }
        
        try:
            # 获取IP地址
            info['ip_address'] = socket.gethostbyname(target)
            info['hostname'] = target
            
            # 反向DNS查询
            try:
                info['reverse_dns'] = socket.gethostbyaddr(info['ip_address'])[0]
            except:
                pass
        
        except Exception as e:
            self.log_debug(f"获取网络信息失败: {str(e)}")
        
        return info
    
    def _detect_os(self, target, timeout):
        """
        简单的操作系统指纹识别
        
        Args:
            target: 目标IP
            timeout: 超时时间
        
        Returns:
            str: 操作系统猜测
        """
        try:
            # 使用TTL值进行初步判断
            # Windows通常TTL=128，Linux通常TTL=64
            
            import subprocess
            import platform
            
            # Ping目标
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), target]
            else:
                cmd = ['ping', '-c', '1', '-W', str(timeout), target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            
            if result.returncode == 0:
                output = result.stdout
                
                if 'ttl=128' in output.lower() or 'TTL=128' in output:
                    return 'Windows (TTL=128)'
                elif 'ttl=64' in output.lower() or 'TTL=64' in output:
                    return 'Linux/Unix (TTL=64)'
                elif 'ttl=255' in output.lower() or 'TTL=255' in output:
                    return 'Cisco/Network Device (TTL=255)'
            
            return 'Unknown'
        
        except:
            return 'Unknown'
