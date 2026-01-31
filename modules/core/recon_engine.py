"""
核心扫描引擎
协调各个扫描模块，管理扫描任务
"""

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.scanning.subdomain_scanner import SubdomainScanner
from modules.scanning.port_scanner import PortScanner
from modules.scanning.service_scanner import ServiceScanner
from modules.scanning.dns_scanner import DNSScanner, WhoisScanner
from modules.scanning.directory_scanner import DirectoryScanner
from modules.scanning.vulnerability_scanner import VulnerabilityScanner
from modules.scanning.ssl_scanner import SSLScanner, NetworkScanner
from modules.utils.logger import get_logger


class ReconEngine:
    """扫描引擎主类"""
    
    def __init__(self, config, logger=None):
        """
        初始化扫描引擎
        
        Args:
            config: 配置字典
            logger: 日志记录器
        """
        self.config = config
        self.logger = logger or get_logger()
        
        # 初始化各个扫描器
        self.scanners = {
            'subdomain': SubdomainScanner(config, self.logger),
            'port': PortScanner(config, self.logger),
            'service': ServiceScanner(config, self.logger),
            'dns': DNSScanner(config, self.logger),
            'whois': WhoisScanner(config, self.logger),
            'dir': DirectoryScanner(config, self.logger),
            'vuln': VulnerabilityScanner(config, self.logger),
            'ssl': SSLScanner(config, self.logger),
            'network': NetworkScanner(config, self.logger)
        }
        
        self.results = {}
        self.lock = threading.Lock()
    
    def scan_target(self, target, modules, threads=None, timeout=None, wordlist=None):
        """
        扫描单个目标
        
        Args:
            target: 目标域名或IP
            modules: 启用的模块列表
            threads: 线程数
            timeout: 超时时间
            wordlist: 自定义字典文件
        
        Returns:
            dict: 扫描结果
        """
        self.logger.info(f"开始扫描目标: {target}")
        start_time = time.time()
        
        # 设置参数
        if threads is None:
            threads = self.config.get('scan', {}).get('default_threads', 30)
        if timeout is None:
            timeout = self.config.get('scan', {}).get('default_timeout', 5)
        
        target_results = {
            'target': target,
            'start_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'modules': modules,
            'results': {},
            'status': 'running'
        }
        
        try:
            # 使用线程池执行扫描任务
            with ThreadPoolExecutor(max_workers=min(len(modules), threads)) as executor:
                future_to_module = {}
                
                for module in modules:
                    if module in self.scanners:
                        scanner = self.scanners[module]
                        # 提交扫描任务
                        future = executor.submit(
                            self._scan_module_wrapper,
                            scanner, target, timeout, wordlist
                        )
                        future_to_module[future] = module
                
                # 收集结果
                for future in as_completed(future_to_module):
                    module = future_to_module[future]
                    try:
                        result = future.result()
                        with self.lock:
                            target_results['results'][module] = result
                        self.logger.info(f"模块 {module} 完成扫描")
                    except Exception as e:
                        self.logger.error(f"模块 {module} 扫描出错: {str(e)}")
                        with self.lock:
                            target_results['results'][module] = {'error': str(e)}
            
            target_results['status'] = 'completed'
            
        except Exception as e:
            self.logger.error(f"扫描目标 {target} 时出错: {str(e)}")
            target_results['status'] = 'error'
            target_results['error'] = str(e)
        
        end_time = time.time()
        target_results['end_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        target_results['duration'] = round(end_time - start_time, 2)
        
        self.logger.info(f"完成扫描 {target}, 耗时: {target_results['duration']}秒")
        return target_results
    
    def _scan_module_wrapper(self, scanner, target, timeout, wordlist):
        """
        扫描模块包装器，统一处理异常
        
        Args:
            scanner: 扫描器实例
            target: 目标
            timeout: 超时时间
            wordlist: 字典文件
        
        Returns:
            dict: 扫描结果
        """
        try:
            if hasattr(scanner, 'scan'):
                return scanner.scan(target, timeout, wordlist)
            else:
                return {'error': '扫描器缺少scan方法'}
        except Exception as e:
            raise e
    
    def scan_multiple_targets(self, targets, modules, threads=None, timeout=None, wordlist=None):
        """
        扫描多个目标
        
        Args:
            targets: 目标列表
            modules: 启用的模块列表
            threads: 线程数
            timeout: 超时时间
            wordlist: 字典文件
        
        Returns:
            dict: 所有目标的扫描结果
        """
        if threads is None:
            threads = self.config.get('scan', {}).get('default_threads', 30)
        
        results = {}
        total_targets = len(targets)
        
        self.logger.info(f"开始批量扫描 {total_targets} 个目标")
        
        # 使用线程池扫描多个目标
        with ThreadPoolExecutor(max_workers=min(total_targets, threads // 2)) as executor:
            future_to_target = {}
            
            for target in targets:
                future = executor.submit(
                    self.scan_target, target, modules, threads, timeout, wordlist
                )
                future_to_target[future] = target
            
            # 收集结果
            for i, future in enumerate(as_completed(future_to_target), 1):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results[target] = result
                    self.logger.info(f"进度: {i}/{total_targets} - 完成 {target}")
                except Exception as e:
                    self.logger.error(f"扫描 {target} 失败: {str(e)}")
                    results[target] = {'error': str(e)}
        
        self.logger.info(f"批量扫描完成，成功: {len(results)}/{total_targets}")
        return results
    
    def get_scanner_info(self):
        """
        获取扫描器信息
        
        Returns:
            dict: 扫描器信息
        """
        info = {}
        for name, scanner in self.scanners.items():
            info[name] = {
                'name': name,
                'description': getattr(scanner, 'description', '无描述'),
                'version': getattr(scanner, 'version', '1.0'),
                'author': getattr(scanner, 'author', '未知')
            }
        return info
    
    def stop_scan(self):
        """停止扫描"""
        # TODO: 实现扫描停止功能
        pass
    
    def get_progress(self):
        """
        获取扫描进度
        
        Returns:
            dict: 进度信息
        """
        # TODO: 实现进度获取功能
        return {'progress': 0, 'status': 'unknown'}
