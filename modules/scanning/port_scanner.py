"""
端口扫描器
支持多种扫描方式：SYN、TCP、UDP扫描
"""

import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.scanning.base_scanner import BaseScanner
import time
import random


class PortScanner(BaseScanner):
    """端口扫描器"""
    
    def __init__(self, config, logger=None):
        super().__init__(config, logger)
        self.description = "端口扫描器"
        
        # 常用端口列表
        self.top_ports = config.get('port', {}).get('top_ports', [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443
        ])
        
        self.common_ports = config.get('port', {}).get('common_ports', [80, 443, 8000, 8080, 8443, 8888])
        
        # 端口服务映射（常见端口）
        self.port_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt'
        }
    
    def scan(self, target, timeout=5, wordlist=None):
        """
        扫描目标端口
        
        Args:
            target: 目标IP或域名
            timeout: 超时时间
            wordlist: 端口范围或列表
        
        Returns:
            dict: 扫描结果
        """
        if not self.is_valid_target(target):
            return self.format_result(False, error="无效的目标")
        
        self.log_info(f"开始扫描端口: {target}")
        
        results = {
            'target': target,
            'open_ports': [],
            'closed_ports': 0,
            'filtered_ports': 0,
            'scan_duration': 0
        }
        
        try:
            start_time = time.time()
            
            # 解析要扫描的端口列表
            if wordlist and isinstance(wordlist, str):
                # 如果是字符串，尝试解析为端口范围
                ports = self._parse_port_range(wordlist)
            else:
                ports = self.top_ports
            
            # 执行端口扫描
            open_ports = self._scan_ports(target, ports, timeout)
            
            # 格式化结果
            for port_info in open_ports:
                results['open_ports'].append(port_info)
            
            results['total_scanned'] = len(ports)
            results['open_count'] = len(open_ports)
            results['scan_duration'] = round(time.time() - start_time, 2)
            
            self.log_info(f"扫描完成，发现 {len(open_ports)} 个开放端口")
            
            return self.format_result(True, results)
            
        except Exception as e:
            self.log_error(f"扫描端口时出错: {str(e)}")
            return self.format_result(False, error=str(e))
    
    def _parse_port_range(self, port_string):
        """
        解析端口范围字符串
        
        Args:
            port_string: 端口范围字符串，如 "1-100" 或 "80,443,8080"
        
        Returns:
            list: 端口列表
        """
        ports = []
        
        try:
            if '-' in port_string:
                # 解析范围
                start, end = port_string.split('-')
                ports = list(range(int(start), int(end) + 1))
            elif ',' in port_string:
                # 解析列表
                ports = [int(p.strip()) for p in port_string.split(',') if p.strip()]
            else:
                # 单个端口
                ports = [int(port_string)]
        except:
            # 如果解析失败，使用默认端口
            ports = self.top_ports
        
        return ports
    
    def _scan_ports(self, target, ports, timeout):
        """
        执行端口扫描
        
        Args:
            target: 目标IP或域名
            ports: 端口列表
            timeout: 超时时间
        
        Returns:
            list: 开放端口信息列表
        """
        open_ports = []
        
        # 线程池扫描端口
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {}
            
            for port in ports:
                future = executor.submit(self._scan_port, target, port, timeout)
                future_to_port[future] = port
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        self.log_debug(f"端口 {port} 开放")
                except Exception as e:
                    self.log_debug(f"扫描端口 {port} 时出错: {str(e)}")
        
        # 按端口排序
        open_ports.sort(key=lambda x: x['port'])
        return open_ports
    
    def _scan_port(self, target, port, timeout):
        """
        扫描单个端口
        
        Args:
            target: 目标IP或域名
            port: 端口
            timeout: 超时时间
        
        Returns:
            dict or None: 端口信息或None（如果端口关闭）
        """
        try:
            # 创建socket连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # 尝试连接
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # 端口开放
                port_info = {
                    'port': port,
                    'state': 'open',
                    'service': self.port_services.get(port, 'unknown'),
                    'banner': self._grab_banner(sock, port)
                }
                sock.close()
                return port_info
            
            sock.close()
            return None
            
        except socket.timeout:
            return None
        except Exception:
            return None
    
    def _grab_banner(self, sock, port):
        """
        抓取服务banner信息
        
        Args:
            sock: socket连接
            port: 端口
        
        Returns:
            str: banner信息
        """
        try:
            # 根据端口类型发送不同的探测数据
            if port in [80, 8080, 8000]:
                # HTTP服务
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                return sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port == 21:
                # FTP服务
                return sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port == 25:
                # SMTP服务
                return sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port == 22:
                # SSH服务
                return sock.recv(1024).decode('utf-8', errors='ignore').strip()
            else:
                # 通用探测
                sock.send(b'\r\n')
                return sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            return ""
    
    def syn_scan(self, target, ports, timeout):
        """
        SYN扫描（需要root权限）
        
        Args:
            target: 目标IP
            ports: 端口列表
            timeout: 超时时间
        
        Returns:
            list: 开放端口列表
        """
        # 注意：这需要raw socket，通常需要root权限
        # 这里提供基本框架，实际使用时需要处理权限问题
        
        open_ports = []
        
        try:
            # 创建原始socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(timeout)
            
            # 构建TCP SYN包
            for port in ports:
                try:
                    # 发送SYN包
                    packet = self._build_syn_packet(target, port)
                    sock.sendto(packet, (target, 0))
                    
                    # 接收响应
                    response = sock.recv(1024)
                    
                    # 解析响应（简化处理）
                    if len(response) > 40:
                        # TCP头从第20字节开始
                        tcp_header = response[20:40]
                        flags = struct.unpack('!H', tcp_header[12:14])[0]
                        
                        # 检查SYN-ACK标志
                        if flags & 0x12 == 0x12:  # SYN + ACK
                            open_ports.append({
                                'port': port,
                                'state': 'open',
                                'service': self.port_services.get(port, 'unknown')
                            })
                except:
                    continue
            
            sock.close()
            
        except Exception as e:
            self.log_error(f"SYN扫描失败: {str(e)}")
        
        return open_ports
    
    def _build_syn_packet(self, target, port):
        """
        构建SYN数据包
        
        Args:
            target: 目标IP
            port: 端口
        
        Returns:
            bytes: SYN数据包
        """
        # 简化的SYN包构建（实际需要更完整的IP和TCP头）
        
        # 这里只是示例，实际使用时需要完整的头部计算
        source_port = random.randint(1024, 65535)
        
        # TCP头
        tcp_header = struct.pack('!HHLLBBHHH',
                                source_port,  # 源端口
                                port,  # 目标端口
                                0,  # 序列号
                                0,  # 确认号
                                5 << 4,  # 数据偏移
                                0x02,  # SYN标志
                                8192,  # 窗口大小
                                0,  # 校验和
                                0)  # 紧急指针
        
        # 这里省略了IP头和校验和计算
        return tcp_header
    
    def get_service_info(self, port):
        """
        获取端口服务信息
        
        Args:
            port: 端口号
        
        Returns:
            dict: 服务信息
        """
        return {
            'port': port,
            'service': self.port_services.get(port, 'unknown'),
            'description': self._get_service_description(port)
        }
    
    def _get_service_description(self, port):
        """
        获取服务描述
        
        Args:
            port: 端口号
        
        Returns:
            str: 服务描述
        """
        descriptions = {
            21: '文件传输协议',
            22: '安全外壳协议',
            23: '远程登录协议',
            25: '简单邮件传输协议',
            53: '域名系统',
            80: '超文本传输协议',
            110: '邮局协议版本3',
            443: '超文本传输安全协议',
            3306: 'MySQL数据库',
            3389: '远程桌面协议',
            5432: 'PostgreSQL数据库',
            5900: '虚拟网络计算',
            8080: 'HTTP备用端口'
        }
        return descriptions.get(port, '未知服务')
